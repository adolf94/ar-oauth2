using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Ar.Auth.OpenId.Tests;

/// <summary>
/// Minimal in-proc OIDC provider used by the BFF integration tests (T0.1 decision):
/// serves discovery, JWKS, /authorize (issues code + echoes state), and /token
/// (verifies PKCE S256, returns a signed id_token for sub=user-42).
/// </summary>
public sealed class StubOidcServer : IAsyncDisposable
{
    private readonly RSA _rsa = RSA.Create(2048);
    private WebApplication? _app;
    private readonly JwtSecurityTokenHandler _tokenHandler = new();
    private readonly ConcurrentDictionary<string, string> _refreshTokens = new(); // token → nonce
    private int _refreshGrantCount;

    public string Authority { get; private set; } = "";

    /// <summary>Number of refresh_token grants served (single-flight assertion).</summary>
    public int RefreshGrantCount => _refreshGrantCount;

    /// <summary>Simulates server-side revocation: every issued refresh token becomes invalid.</summary>
    public void RevokeAllRefreshTokens() => _refreshTokens.Clear();

    /// <summary>
    /// A signed access-token JWT (iss=Authority, aud=bff-test-client) for the given sub —
    /// lets tests exercise the JwtBearer path with an identity distinct from the
    /// cookie-login user.
    /// </summary>
    public string CreateAccessToken(string sub)
    {
        return _tokenHandler.WriteToken(_tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Authority,
            Audience = "bff-test-client",
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(_rsa), SecurityAlgorithms.RsaSha256),
            Subject = new ClaimsIdentity(new List<Claim> { new("sub", sub) }),
            IssuedAt = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddMinutes(10)
        }));
    }

    /// <summary>
    /// A signed ar-auth session-token JWT (iss=aud=Authority, type=session) — mimics the
    /// auth server's shared-Domain session cookie contents, for the legacy
    /// AllowSessionCookie fallback.
    /// </summary>
    public string CreateSessionToken(string sub)
    {
        return _tokenHandler.WriteToken(_tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Authority,
            Audience = Authority, // session JWTs: audience = issuer
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(_rsa), SecurityAlgorithms.RsaSha256),
            Subject = new ClaimsIdentity(new List<Claim>
            {
                new("sub", sub),
                new("type", "session")
            }),
            IssuedAt = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddMinutes(10)
        }));
    }

    private string CreateIdToken(string clientId, string nonce)
    {
        return _tokenHandler.WriteToken(_tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Authority,
            Audience = clientId,
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(_rsa), SecurityAlgorithms.RsaSha256),
            Subject = new ClaimsIdentity(new List<Claim>
            {
                new("sub", "user-42"),
                new("email", "user@example.com"),
                new("name", "Test User"),
                new("nonce", nonce)
            }),
            IssuedAt = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddMinutes(10)
        }));
    }

    public static async Task<StubOidcServer> StartAsync()
    {
        var server = new StubOidcServer();
        // Keep "sub" raw — the default outbound claim map would rename it.
        server._tokenHandler.OutboundClaimTypeMap.Clear();

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(o => o.Listen(IPAddress.Loopback, 0));

        var codes = new ConcurrentDictionary<string, AuthRecord>();
        var app = builder.Build();

        app.MapGet("/.well-known/openid-configuration", () => Results.Json(new
        {
            issuer = server.Authority,
            authorization_endpoint = $"{server.Authority}/authorize",
            token_endpoint = $"{server.Authority}/token",
            jwks_uri = $"{server.Authority}/jwks",
            response_types_supported = new[] { "code" },
            code_challenge_methods_supported = new[] { "S256" },
            scopes_supported = new[] { "openid", "profile" },
            token_endpoint_auth_methods_supported = new[] { "none" }
        }));

        app.MapGet("/jwks", () => Results.Text(server.BuildJwks(), "application/json"));

        app.MapGet("/authorize", (HttpRequest req) =>
        {
            var redirectUri = req.Query["redirect_uri"].ToString();
            if (string.IsNullOrEmpty(redirectUri))
            {
                return Results.BadRequest("missing redirect_uri");
            }

            // PKCE is mandatory for public clients (the ar-auth server enforces this too).
            var challenge = req.Query["code_challenge"].ToString();
            var method = req.Query["code_challenge_method"].ToString();
            if (string.IsNullOrEmpty(challenge))
            {
                return Results.BadRequest("missing code_challenge");
            }

            var state = req.Query["state"].ToString();
            var nonce = req.Query["nonce"].ToString();
            var scope = req.Query["scope"].ToString();
            var code = "stub-" + Guid.NewGuid().ToString("N");
            codes[code] = new AuthRecord(redirectUri, state, nonce, challenge, method, scope);

            var sep = redirectUri.Contains('?') ? '&' : '?';
            return Results.Redirect(
                $"{redirectUri}{sep}code={Uri.EscapeDataString(code)}" +
                $"&state={Uri.EscapeDataString(state)}&scope={Uri.EscapeDataString(scope)}");
        });

        app.MapPost("/token", async (HttpRequest req) =>
        {
            var form = await req.ReadFormAsync();
            var grantType = form["grant_type"].ToString();

            if (grantType == "refresh_token")
            {
                // Counts refresh round-trips (attempts), successful or not.
                Interlocked.Increment(ref server._refreshGrantCount);

                var provided = form["refresh_token"].ToString();
                var clientId = form["client_id"].ToString();

                if (string.IsNullOrEmpty(provided) || clientId != "bff-test-client")
                {
                    return Results.Json(new
                    {
                        error = "invalid_request",
                        error_description = "refresh_token and client_id are required."
                    }, statusCode: 400);
                }

                // One-time-use rotation exactly like the ar-auth server: burn on read.
                if (!server._refreshTokens.TryRemove(provided, out var nonce))
                {
                    return Results.Json(new
                    {
                        error = "invalid_grant",
                        error_description = "Refresh token is invalid, expired, or already used."
                    }, statusCode: 400);
                }

                var rotated = "stub-refresh-" + Guid.NewGuid().ToString("N");
                server._refreshTokens[rotated] = nonce;

                return Results.Json(new
                {
                    access_token = "stub-access-token-" + Guid.NewGuid().ToString("N"),
                    token_type = "Bearer",
                    expires_in = 3600,
                    id_token = server.CreateIdToken(clientId, nonce),
                    refresh_token = rotated,
                    scope = "openid profile"
                });
            }

            var code = form["code"].ToString();

            // Unknown or deliberately burned code → invalid_grant (consumed-code test).
            if (code == "burned" || !codes.TryGetValue(code, out var record))
            {
                return Results.Json(new
                {
                    error = "invalid_grant",
                    error_description = "Authorization code is invalid or expired."
                }, statusCode: 400);
            }

            // Verify PKCE S256 exactly like a real provider.
            if (record.CodeChallengeMethod == "S256")
            {
                var verifier = form["code_verifier"].ToString();
                var computed = Base64UrlSha256(verifier);
                if (computed != record.CodeChallenge)
                {
                    return Results.Json(new
                    {
                        error = "invalid_grant",
                        error_description = "PKCE verification failed."
                    }, statusCode: 400);
                }
            }

            codes.TryRemove(code, out _); // one-time use

            var refreshToken = "stub-refresh-" + Guid.NewGuid().ToString("N");
            server._refreshTokens[refreshToken] = record.Nonce;

            return Results.Json(new
            {
                access_token = "stub-access-token",
                token_type = "Bearer",
                expires_in = 3600,
                id_token = server.CreateIdToken(form["client_id"].ToString(), record.Nonce),
                refresh_token = refreshToken,
                scope = record.Scope
            });
        });

        await app.StartAsync();
        server._app = app;
        server.Authority = app.Services
            .GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!
            .Addresses.First()
            .TrimEnd('/');

        return server;
    }

    public ValueTask DisposeAsync() => _app?.DisposeAsync() ?? ValueTask.CompletedTask;

    private string BuildJwks()
    {
        var p = _rsa.ExportParameters(false);
        return JsonSerializer.Serialize(new
        {
            keys = new object[]
            {
                new
                {
                    kty = "RSA",
                    use = "sig",
                    kid = "stub-key",
                    alg = "RS256",
                    n = Base64Url(p.Modulus!),
                    e = Base64Url(p.Exponent!)
                }
            }
        });
    }

    private static string Base64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Base64UrlSha256(string value)
        => Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(value)));

    private sealed record AuthRecord(
        string RedirectUri,
        string State,
        string Nonce,
        string CodeChallenge,
        string CodeChallengeMethod,
        string Scope);
}
