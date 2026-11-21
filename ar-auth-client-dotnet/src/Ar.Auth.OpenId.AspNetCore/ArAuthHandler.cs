namespace Ar.Auth.OpenId.AspNetCore;

/// <summary>
/// The BFF extensibility surface (design doc §3.9): five virtual hook points around the
/// pipeline built in Stages 2–4. Subclass and register via
/// <c>AddArAuthBff&lt;THandler&gt;(...)</c> for typed, DI-injected hooks; or set the
/// matching <see cref="BffEvents"/> delegates for the no-class alternative — both
/// surfaces run the same points and compose (calling <c>base</c> fires the delegate).
///
/// Security-critical work (state, PKCE, correlation, cookie issuance, CSRF checks) lives in
/// the pipeline components and ALWAYS runs. Overriding a hook cannot skip it; NOT calling
/// base merely opts out of the <see cref="BffEvents"/> delegate of the same name.
/// </summary>
public class ArAuthHandler
{
    public ArAuthHandler(BffOptions options, BffPathResolver resolver)
    {
        Options = options;
        Resolver = resolver;
    }

    /// <summary>BFF configuration (paths, cookie scoping, CSRF mode).</summary>
    protected BffOptions Options { get; }

    /// <summary>Public-identity resolver (redirect_uri, cookie path/prefix).</summary>
    protected BffPathResolver Resolver { get; }

    /// <summary>
    /// Before the 302 to the auth server's /authorize. May add extra authorize parameters
    /// (<see cref="BffRedirectContext.ExtraParameters"/>) or adjust the (re-sanitized)
    /// return URL. Base fires <see cref="BffEvents.OnLoginRedirectingAsync"/>.
    /// </summary>
    public virtual Task OnLoginRedirectingAsync(BffRedirectContext ctx)
        => Options.Events.OnLoginRedirectingAsync(ctx);

    /// <summary>
    /// Code exchanged and id_token validated, before the session is issued. May enrich /
    /// replace the principal, adjust the return URL, or <see cref="BffAuthenticatedContext.Reject"/>
    /// to abort without issuing any cookie. Base fires
    /// <see cref="BffEvents.OnAuthenticatedAsync"/>.
    /// </summary>
    public virtual Task OnAuthenticatedAsync(BffAuthenticatedContext ctx)
        => Options.Events.OnAuthenticatedAsync(ctx);

    /// <summary>
    /// Last hook of the login flow: refresh + XSRF cookies are staged, the session is about
    /// to be issued and the user redirected to the final return URL. Base fires
    /// <see cref="BffEvents.OnRedirectingAsync"/>.
    /// </summary>
    public virtual Task OnRedirectingAsync(BffRedirectContext ctx)
        => Options.Events.OnRedirectingAsync(ctx);

    /// <summary>
    /// Logout: the base pipeline (always runs, virtual or not) clears the session and
    /// companion cookies and redirects; the hook observes / extends (e.g. audit).
    /// Base fires <see cref="BffEvents.OnLogoutAsync"/>.
    /// </summary>
    public virtual Task OnLogoutAsync(BffLogoutContext ctx)
        => Options.Events.OnLogoutAsync(ctx);

    /// <summary>
    /// After silent renewal succeeded and the session/parked/XSRF cookies were re-issued
    /// (design doc §3.5). Base fires <see cref="BffEvents.OnRenewedAsync"/>.
    /// </summary>
    public virtual Task OnRenewedAsync(BffRenewalContext ctx)
        => Options.Events.OnRenewedAsync(ctx);
}
