namespace Ar.Auth.OpenId.AspNetCore;

/// <summary>
/// Delegate hooks for the BFF pipeline — the lightweight alternative to subclassing
/// <c>ArAuthHandler</c>. Base implementations own everything security-critical
/// (state, PKCE, correlation, cookie issuance, CSRF checks); hooks are observability,
/// enrichment, and parameterization points. See docs/cookie-auth-plan.md §3.9.
/// </summary>
public class BffEvents
{
    /// <summary>Before the 302 to the auth server's /authorize. May add extra authorize parameters.</summary>
    public Func<BffRedirectContext, Task> OnLoginRedirectingAsync { get; set; } = _ => Task.CompletedTask;

    /// <summary>Code exchanged and validated, before SignInAsync. May enrich the principal,
    /// adjust the return URL, or Reject() to abort (no session is issued).</summary>
    public Func<BffAuthenticatedContext, Task> OnAuthenticatedAsync { get; set; } = _ => Task.CompletedTask;

    /// <summary>Last hook of the login flow: cookies are staged, the session is about to be
    /// issued and the user redirected to the final return URL. May adjust (re-sanitized)
    /// returnUrl.</summary>
    public Func<BffRedirectContext, Task> OnRedirectingAsync { get; set; } = _ => Task.CompletedTask;

    /// <summary>Around logout: local cookie cleanup happens in base; hook observes/extends.</summary>
    public Func<BffLogoutContext, Task> OnLogoutAsync { get; set; } = _ => Task.CompletedTask;

    /// <summary>After silent renewal succeeded and cookies were re-issued.</summary>
    public Func<BffRenewalContext, Task> OnRenewedAsync { get; set; } = _ => Task.CompletedTask;
}
