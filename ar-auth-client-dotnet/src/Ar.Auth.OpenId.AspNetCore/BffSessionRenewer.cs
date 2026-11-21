using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Ar.Auth.OpenId.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Ar.Auth.OpenId.AspNetCore;

/// <summary>Outcome of a silent-renewal attempt.</summary>
internal enum BffRenewOutcome
{
    /// <summary>Session (re-)issued — by this call or by reusing a concurrent renewal.</summary>
    Renewed,

    /// <summary>The parked refresh was definitively rejected (invalid_grant, bad id_token) — drop it.</summary>
    Rejected,

    /// <summary>Transient failure (auth server unreachable, malformed response) — keep the parked cookie.</summary>
    Unavailable,
}

/// <summary>
/// Silent session renewal from the parked refresh cookie (design doc §3.5).
///
/// ar-auth refresh tokens are one-time-use with rotation (§10.A): two concurrent renewals
/// carrying the same token race, and the loser burns a consumed token into a spurious logout.
/// All renewals for one token chain serialize on a per-chain gate; waiters that arrive while
/// a refresh is in flight reuse its result instead of issuing another /token roundtrip.
/// </summary>
public sealed class BffSessionRenewer
{
    /// <summary>
    /// How long a completed renewal can serve as the reuse answer for concurrent requests
    /// carrying the (now consumed) predecessor token. Covers the parallel-401 storm; anything
    /// older is attempted against the auth server directly.
    /// </summary>
    private static readonly TimeSpan ReuseWindow = TimeSpan.FromMinutes(2);

    private readonly BffRefreshStore _store;
    private readonly IOptionsMonitor<OpenIdConnectOptions> _oidc;
    private readonly BffOptions _bff;
    private readonly BffCsrfTokenService _csrf;
    private readonly ArAuthHandler _handler;
    private readonly ConcurrentDictionary<string, ChainState> _chains = new();
    private readonly HttpClient _http;

    public BffSessionRenewer(
        BffRefreshStore store,
        IOptionsMonitor<OpenIdConnectOptions> oidc,
        BffOptions bff,
        BffCsrfTokenService csrf,
        ArAuthHandler handler)
    {
        _store = store;
        _oidc = oidc;
        _bff = bff;
        _csrf = csrf;
        _handler = handler;
        _http = new HttpClient(new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(10)
        });
    }

    internal sealed record RenewedSession(ClaimsPrincipal Principal, string RefreshToken, DateTimeOffset RenewedAt);

    private sealed class ChainState
    {
        public readonly SemaphoreSlim Gate = new(1, 1);
        public RenewedSession? Latest;
    }

    /// <summary>
    /// Attempts to (re-)issue the app session for this request from the parked refresh token.
    /// Must be called while holding no other user-visible state; the per-chain gate makes it
    /// single-flight.
    /// </summary>
    internal async Task<BffRenewOutcome> TryRenewAsync(
        HttpContext ctx,
        string parkedRefresh,
        string cookieName,
        string cookiePath,
        string xsrfCookieName,
        CancellationToken ct)
    {
        var chain = _chains.GetOrAdd(TokenKey(parkedRefresh), _ => new ChainState());

        await chain.Gate.WaitAsync(ct);
        try
        {
            // Single-flight: a concurrent request may have refreshed this exact chain while
            // we queued. Our carried token was consumed by that refresh — reuse its result.
            var latest = chain.Latest;
            if (latest is not null
                && !string.Equals(latest.RefreshToken, parkedRefresh, StringComparison.Ordinal)
                && latest.RenewedAt > DateTimeOffset.UtcNow - ReuseWindow)
            {
                await IssueAsync(ctx, latest, cookieName, cookiePath, xsrfCookieName);
                return BffRenewOutcome.Renewed;
            }

            var (outcome, renewed) = await RefreshAsync(parkedRefresh, ct);
            if (outcome != BffRenewOutcome.Renewed || renewed is null)
            {
                return outcome;
            }

            chain.Latest = renewed;
            await IssueAsync(ctx, renewed, cookieName, cookiePath, xsrfCookieName);
            return BffRenewOutcome.Renewed;
        }
        finally
        {
            chain.Gate.Release();
        }
    }

    /// <summary>Issues the session cookie + re-parks the rotated refresh, then sets ctx.User.</summary>
    private async Task IssueAsync(
        HttpContext ctx,
        RenewedSession session,
        string cookieName,
        string cookiePath,
        string xsrfCookieName)
    {
        await ctx.SignInAsync(BffConstants.SessionScheme, session.Principal);
        _store.Park(ctx, session.RefreshToken, cookieName, cookiePath);

        // Fresh CSRF token alongside the fresh session (design doc §4, layer 3). The
        // request that triggered renewal keeps passing on its OLD still-signed token;
        // the SPA picks the new one up on its next read.
        if (_bff.Csrf != BffCsrfMode.Off)
        {
            _csrf.Issue(ctx, xsrfCookieName, cookiePath, _bff.SessionExpiry);
        }

        ctx.User = session.Principal;

        // Renewal hook (design doc §3.9): everything is already re-issued.
        await _handler.OnRenewedAsync(new BffRenewalContext(ctx, session.Principal));
    }

    private async Task<(BffRenewOutcome Outcome, RenewedSession? Session)> RefreshAsync(
        string refreshToken, CancellationToken ct)
    {
        var o = _oidc.Get(BffConstants.OidcScheme);
        if (o.ConfigurationManager is null)
        {
            return (BffRenewOutcome.Unavailable, null);
        }

        try
        {
            // ConfigurationManager is warmed at host start (BffOidcWarmup) — this is a cache hit.
            var config = await o.ConfigurationManager.GetConfigurationAsync(ct);
            if (string.IsNullOrEmpty(config.TokenEndpoint))
            {
                return (BffRenewOutcome.Unavailable, null);
            }

            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken,
            };
            if (!string.IsNullOrEmpty(o.ClientId))
            {
                form["client_id"] = o.ClientId;
            }

            using var response = await _http.PostAsync(
                config.TokenEndpoint, new FormUrlEncodedContent(form), ct);

            // 400/401: the token itself is bad (consumed, expired, revoked, wrong client) —
            // definitive; the caller deletes the parked cookie. Other failures are transient.
            if (response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized)
            {
                return (BffRenewOutcome.Rejected, null);
            }
            if (!response.IsSuccessStatusCode)
            {
                return (BffRenewOutcome.Unavailable, null);
            }

            var tokens = await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: ct);
            if (tokens is null
                || string.IsNullOrEmpty(tokens.RefreshToken)
                || string.IsNullOrEmpty(tokens.IdToken))
            {
                return (BffRenewOutcome.Unavailable, null);
            }

            // The renewed session mirrors the login principal: claims from a fully
            // validated id_token (issuer, audience, signature against the warm JWKS).
            var principal = await ValidateIdTokenAsync(tokens.IdToken, config, o.TokenValidationParameters, ct);
            if (principal is null)
            {
                return (BffRenewOutcome.Rejected, null);
            }

            return (BffRenewOutcome.Renewed,
                new RenewedSession(principal, tokens.RefreshToken, DateTimeOffset.UtcNow));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return (BffRenewOutcome.Unavailable, null);
        }
        catch (Exception)
        {
            // Transport/parse failures are transient — never burn the parked token for them.
            return (BffRenewOutcome.Unavailable, null);
        }
    }

    private static async Task<ClaimsPrincipal?> ValidateIdTokenAsync(
        string idToken,
        Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration config,
        TokenValidationParameters baseParameters,
        CancellationToken ct)
    {
        try
        {
            var tvp = baseParameters.Clone();
            tvp.ValidIssuer = config.Issuer;
            tvp.IssuerSigningKeys = config.SigningKeys; // warm JWKS from discovery

            var result = await new JsonWebTokenHandler().ValidateTokenAsync(idToken, tvp);
            if (!result.IsValid)
            {
                return null;
            }

            return new ClaimsPrincipal(result.ClaimsIdentity);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Lock/cache key — SHA-256 of the token, never the raw value.</summary>
    private static string TokenKey(string refreshToken)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(refreshToken)));
}
