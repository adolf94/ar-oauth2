using System.Security.Claims;
using System.Text.Encodings.Web;
using Ar.Auth.OpenId.Exceptions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Ar.Auth.OpenId.AspNetCore;

/// <summary>
/// Authenticates requests carrying the auth server's session cookie
/// (see <see cref="ArAuthOptions.CookieName"/>) as a fallback credential when no
/// Authorization header is present. Only active when <see cref="ArAuthOptions.AllowSessionCookie"/>
/// is enabled; otherwise it returns NoResult everywhere and behavior is unchanged.
///
/// Session principals carry sub/email/name only — no roles or scopes — so role- or
/// scope-based authorization still fails cleanly for cookie-authenticated callers.
/// </summary>
public class ArAuthSessionHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    /// <summary>Name of the authentication scheme implemented by this handler.</summary>
    public const string SchemeName = "ArAuthSession";

    private readonly IArAuthClient _client;
    private readonly ArAuthOptions _authOptions;

    public ArAuthSessionHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IArAuthClient client,
        ArAuthOptions authOptions)
        : base(options, logger, encoder)
    {
        _client = client;
        _authOptions = authOptions;
    }

    /// <inheritdoc />
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!_authOptions.AllowSessionCookie)
        {
            return AuthenticateResult.NoResult();
        }

        if (!Request.Cookies.TryGetValue(_authOptions.CookieName, out var token) ||
            string.IsNullOrEmpty(token))
        {
            return AuthenticateResult.NoResult();
        }

        // CSRF guard: only honor the cookie for same-origin (or allow-listed) callers.
        // An explicit Bearer header never reaches this handler (the policy scheme forwards
        // to JwtBearer when one is present).
        var requestOrigin = $"{Request.Scheme}://{Request.Host.Value}";
        if (!SessionCookieGuard.IsOriginAllowed(
                Request.Method,
                Request.Headers.Origin,
                Request.Headers.Referer,
                requestOrigin,
                _authOptions.AllowedCookieOrigins))
        {
            return AuthenticateResult.NoResult();
        }

        try
        {
            ClaimsPrincipal principal = await _client.ValidateSessionTokenAsync(token);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }
        catch (TokenValidationException ex)
        {
            return AuthenticateResult.Fail(ex);
        }
    }
}
