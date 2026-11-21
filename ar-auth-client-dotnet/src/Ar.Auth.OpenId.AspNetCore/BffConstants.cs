namespace Ar.Auth.OpenId.AspNetCore;

/// <summary>
/// Scheme names and cookie names used by the BFF integration. Cookie names carry the
/// collision-safe per-app prefix (T0.2) so multiple apps on one host cannot collide.
/// </summary>
public static class BffConstants
{
    /// <summary>App-local session cookie authentication scheme.</summary>
    public const string SessionScheme = "ArAuth.Bff.Session";

    /// <summary>
    /// Policy scheme installed by the BFF (the default authenticate scheme): forwards
    /// per request to JwtBearer (Authorization header), then the app session scheme,
    /// then — only when enabled — the auth-server session cookie handler.
    /// </summary>
    public const string AuthScheme = "ArAuth.Bff.Policy";

    /// <summary>OpenID Connect remote-authentication scheme (code flow, PKCE).</summary>
    public const string OidcScheme = "ArAuth.Bff.Oidc";

    /// <summary>{prefix}ar-auth.session — encrypted app ticket, HttpOnly.</summary>
    public static string SessionCookieName(string prefix) => $"{prefix}ar-auth.session";

    /// <summary>{prefix}ar-auth.refresh — parked refresh token (Stage 3), encrypted, HttpOnly.</summary>
    public static string RefreshCookieName(string prefix) => $"{prefix}ar-auth.refresh";

    /// <summary>{prefix}XSRF-TOKEN — signed double-submit CSRF token (Stage 4), readable by JS.</summary>
    public static string XsrfCookieName(string prefix) => $"{prefix}XSRF-TOKEN";

    /// <summary>Header the SPA must echo on unsafe cookie-authenticated requests.</summary>
    public const string CsrfHeaderName = "X-CSRF-Token";

    /// <summary>Accepted alias (Angular's native convention).</summary>
    public const string CsrfHeaderAlias = "X-XSRF-TOKEN";

    /// <summary>{prefix}ar-auth.correlation.* — single-use login correlation cookie.</summary>
    public static string CorrelationCookieBaseName(string prefix) => $"{prefix}ar-auth.correlation";

    /// <summary>{prefix}ar-auth.nonce.* — OIDC nonce cookie.</summary>
    public static string NonceCookieBaseName(string prefix) => $"{prefix}ar-auth.nonce";
}
