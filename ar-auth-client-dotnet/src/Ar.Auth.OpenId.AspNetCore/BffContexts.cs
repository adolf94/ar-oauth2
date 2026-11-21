using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace Ar.Auth.OpenId.AspNetCore;

/// <summary>
/// Context for redirect hooks: login start (may add authorize parameters) and the final
/// post-login redirect.
/// </summary>
public class BffRedirectContext
{
    public BffRedirectContext(HttpContext httpContext, string? returnUrl)
    {
        HttpContext = httpContext;
        ReturnUrl = returnUrl;
    }

    /// <summary>The current request.</summary>
    public HttpContext HttpContext { get; }

    /// <summary>
    /// Local return URL the user lands on after the flow completes. Must remain
    /// root-relative — handlers validate and reject absolute/foreign URLs (open-redirect guard).
    /// </summary>
    public string? ReturnUrl { get; set; }

    /// <summary>
    /// Extra query parameters appended to the /authorize redirect.
    /// Only honored by the login-redirect hook.
    /// </summary>
    public IDictionary<string, string> ExtraParameters { get; } = new Dictionary<string, string>();
}

/// <summary>
/// Context for the authenticated hook: the code was exchanged and validated, and the
/// session is about to be issued. Enrich the principal, adjust the return URL, or
/// Reject() to abort the login without issuing a session.
/// </summary>
public class BffAuthenticatedContext
{
    public BffAuthenticatedContext(HttpContext httpContext, ClaimsPrincipal principal, string? returnUrl)
    {
        HttpContext = httpContext;
        Principal = principal;
        ReturnUrl = returnUrl;
    }

    /// <summary>The current request.</summary>
    public HttpContext HttpContext { get; }

    /// <summary>
    /// Principal built from the validated tokens. Replace or enrich freely (e.g. claims
    /// from a local database) — this is what gets signed into the session cookie.
    /// </summary>
    public ClaimsPrincipal Principal { get; set; }

    /// <summary>Local return URL, validated root-relative. May be adjusted.</summary>
    public string? ReturnUrl { get; set; }

    /// <summary>True after <see cref="Reject"/> was called — no session will be issued.</summary>
    public bool Rejected { get; private set; }

    /// <summary>Reason recorded by <see cref="Reject"/>.</summary>
    public string? RejectReason { get; private set; }

    /// <summary>
    /// Aborts the login: no session or refresh cookie is written; the user is redirected
    /// to the login path with the error surfaced.
    /// </summary>
    public void Reject(string reason)
    {
        Rejected = true;
        RejectReason = reason;
    }
}

/// <summary>Context for the logout hook: local cookies are cleaned by base.</summary>
public class BffLogoutContext
{
    public BffLogoutContext(HttpContext httpContext, ClaimsPrincipal? principal, string? returnUrl)
    {
        HttpContext = httpContext;
        Principal = principal;
        ReturnUrl = returnUrl;
    }

    /// <summary>The current request.</summary>
    public HttpContext HttpContext { get; }

    /// <summary>The authenticated principal, if a valid session was present. Null otherwise.</summary>
    public ClaimsPrincipal? Principal { get; }

    /// <summary>Local return URL, validated root-relative. May be adjusted.</summary>
    public string? ReturnUrl { get; set; }
}

/// <summary>Context for the silent-renewal hook: cookies were re-issued from the parked refresh token.</summary>
public class BffRenewalContext
{
    public BffRenewalContext(HttpContext httpContext, ClaimsPrincipal principal)
    {
        HttpContext = httpContext;
        Principal = principal;
    }

    /// <summary>The current request.</summary>
    public HttpContext HttpContext { get; }

    /// <summary>The principal of the freshly re-issued session.</summary>
    public ClaimsPrincipal Principal { get; }
}
