namespace Ar.Auth.OpenId.AspNetCore;

/// <summary>
/// Configuration for the ArAuth BFF (Backend-for-Frontend) integration: same-domain SPAs
/// whose API processes the OIDC login callback and issues an app-local HttpOnly session
/// cookie, so no token is ever held in JavaScript. See docs/cookie-auth-plan.md §3.
/// </summary>
public class BffOptions
{
    /// <summary>Default route the middleware responds on for login (internal path).</summary>
    public const string DefaultLoginPath = "/auth/login";

    /// <summary>Default route the middleware responds on for the OIDC callback (internal path).</summary>
    public const string DefaultCallbackPath = "/auth/callback";

    /// <summary>Default route the middleware responds on for logout (internal path).</summary>
    public const string DefaultLogoutPath = "/auth/logout";

    /// <summary>
    /// Route the app's pipeline responds on for login. This is the path the app sees —
    /// after a reverse proxy has stripped its public prefix (see <see cref="PublicBaseUrl"/>).
    /// </summary>
    public string LoginPath { get; set; } = DefaultLoginPath;

    /// <summary>
    /// Route the app's pipeline responds on for the OIDC callback. The auth server
    /// redirects here with <c>?code=…&amp;state=…</c>.
    /// </summary>
    public string CallbackPath { get; set; } = DefaultCallbackPath;

    /// <summary>
    /// Route the app's pipeline responds on for logout. Clears local cookies (session,
    /// refresh, XSRF) and redirects back to the app.
    /// </summary>
    public string LogoutPath { get; set; } = DefaultLogoutPath;

    /// <summary>
    /// Base URL as the browser and the auth server see it, e.g.
    /// "https://apps.adolfrey.com/app/api". Required when a reverse proxy silently strips a
    /// path prefix (public URL /app/api/auth/callback, app sees /auth/callback); derived
    /// from X-Forwarded-Prefix / UsePathBase when those are available. When set,
    /// <c>redirect_uri = PublicBaseUrl + CallbackPath</c> and cookies are scoped to its path.
    /// </summary>
    public string? PublicBaseUrl { get; set; }

    /// <summary>
    /// Browser-visible path prefix that scopes ALL BFF cookies (session, refresh,
    /// correlation, XSRF). Cookies are matched against the path the browser requests, so
    /// this must be the PUBLIC path even when routes are internal. Defaults to the resolved
    /// public base path; set explicitly for multi-app-per-host isolation, e.g. "/application1/".
    /// </summary>
    public string? CookiePath { get; set; }

    /// <summary>
    /// App session lifetime. Renewal is silent via the parked refresh token while it stays
    /// valid (ar-auth refresh tokens rotate on each use with a sliding 30-day window).
    /// </summary>
    public TimeSpan SessionExpiry { get; set; } = TimeSpan.FromHours(8);

    /// <summary>
    /// CSRF protection for cookie-authenticated unsafe requests. Default is the signed
    /// double-submit token (XSRF-TOKEN cookie + X-CSRF-Token header, HMAC-signed so
    /// sibling-subdomain cookie tossing cannot forge it). See docs/cookie-auth-plan.md §4.
    /// </summary>
    public BffCsrfMode Csrf { get; set; } = BffCsrfMode.SignedDoubleSubmit;

    /// <summary>
    /// Prefix applied to all BFF cookie names, keeping multiple apps on one host from
    /// colliding. Null (default) derives it from the effective cookie path
    /// ("/application1/" → "application1."; root "/" → no prefix).
    /// </summary>
    public string? CookieNamePrefix { get; set; }

    /// <summary>
    /// Hook delegates invoked by the default handler at the five pipeline points.
    /// A subclassed handler (AddArAuthBff&lt;THandler&gt;) may override the virtual methods
    /// instead — both surfaces run the same hooks.
    /// </summary>
    public BffEvents Events { get; } = new();
}

/// <summary>CSRF protection mode for cookie-authenticated unsafe requests.</summary>
public enum BffCsrfMode
{
    /// <summary>
    /// Signed double-submit: HMAC-signed XSRF-TOKEN cookie (readable by JS) must be echoed
    /// in the X-CSRF-Token header on unsafe cookie-authenticated requests.
    /// </summary>
    SignedDoubleSubmit,

    /// <summary>CSRF token enforcement off. SameSite + Origin checks (always on) remain.</summary>
    Off
}
