using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Ar.Auth.OpenId.AspNetCore;

/// <summary>
/// Intercepts the BFF routes: <see cref="BffOptions.LoginPath"/> (challenge the OIDC
/// handler) and <see cref="BffOptions.LogoutPath"/> (clear local cookies), plus the
/// silent session renewal from the parked refresh cookie (design doc §3.5).
///
/// The <see cref="BffOptions.CallbackPath"/> is deliberately NOT handled here: the
/// OpenID Connect remote handler processes it inside UseAuthentication (request-handler
/// schemes are given the callback before this middleware ever runs), which is also why the
/// callback naturally bypasses [Authorize].
///
/// Required pipeline order:
///   app.UseAuthentication().UseArAuthBff().UseAuthorization();
/// </summary>
public sealed class ArAuthBffMiddleware
{
    /// <summary>HttpContext.Items key carrying login-hook parameters to the OIDC event.</summary>
    internal const string ExtraParametersItemKey = "ArAuthBff.ExtraParameters";

    private readonly RequestDelegate _next;
    private readonly BffOptions _bff;
    private readonly BffPathResolver _resolver;
    private readonly BffRefreshStore _refreshStore;
    private readonly BffSessionRenewer _renewer;
    private readonly BffCsrfTokenService _csrf;
    private readonly ArAuthHandler _handler;

    public ArAuthBffMiddleware(
        RequestDelegate next,
        BffOptions bff,
        BffPathResolver resolver,
        BffRefreshStore refreshStore,
        BffSessionRenewer renewer,
        BffCsrfTokenService csrf,
        ArAuthHandler handler)
    {
        _next = next;
        _bff = bff;
        _resolver = resolver;
        _refreshStore = refreshStore;
        _renewer = renewer;
        _csrf = csrf;
        _handler = handler;
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        if (HttpMethods.IsGet(ctx.Request.Method) && ctx.Request.Path == _bff.LoginPath)
        {
            await HandleLoginAsync(ctx);
            return;
        }

        if ((HttpMethods.IsGet(ctx.Request.Method) || HttpMethods.IsPost(ctx.Request.Method))
            && ctx.Request.Path == _bff.LogoutPath)
        {
            await HandleLogoutAsync(ctx);
            return;
        }

        // ── Silent renewal (§3.5): expired/missing session + valid parked refresh ──
        // Re-issues session + parked cookies invisibly; runs for every request that is not
        // already authenticated, so the SPA never needs to know renewal happened.
        if (ShouldAttemptRenewal(ctx))
        {
            await TryRenewSessionAsync(ctx);
        }

        // ── CSRF (§4, layer 3): signed double-submit on unsafe cookie-authenticated calls ──
        // Bearer requests are exempt (attacker JS cannot forge Authorization headers), and
        // so are anonymous requests (401 is the response there — 403 would mislead the SPA).
        if (RequiresCsrfCheck(ctx) && !await IsCsrfValidAsync(ctx))
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        await _next(ctx);
    }

    private static bool ShouldAttemptRenewal(HttpContext ctx)
    {
        return !ctx.User.Identity?.IsAuthenticated == true
            && !ctx.Request.Headers.ContainsKey("Authorization"); // Bearer callers park nothing
    }

    private static bool RequiresCsrfCheck(HttpContext ctx)
    {
        if (IsSafeMethod(ctx.Request.Method))
        {
            return false;
        }

        // Only the cookie-authenticated path is CSRF-exposed.
        return ctx.User.Identity?.IsAuthenticated == true
            && !ctx.Request.Headers.ContainsKey("Authorization");
    }

    private static bool IsSafeMethod(string method)
        => HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method)
            || HttpMethods.IsTrace(method);

    private ValueTask<bool> IsCsrfValidAsync(HttpContext ctx)
    {
        if (_bff.Csrf == BffCsrfMode.Off)
        {
            return ValueTask.FromResult(true);
        }

        var xsrfCookieName = BffConstants.XsrfCookieName(_resolver.GetCookieNamePrefix());
        var cookieValue = ctx.Request.Cookies[xsrfCookieName];
        var header = ctx.Request.Headers[BffConstants.CsrfHeaderName].ToString();
        if (string.IsNullOrEmpty(header))
        {
            header = ctx.Request.Headers[BffConstants.CsrfHeaderAlias].ToString();
        }

        return ValueTask.FromResult(_csrf.Validate(header, cookieValue));
    }

    private async Task TryRenewSessionAsync(HttpContext ctx)
    {
        var prefix = _resolver.GetCookieNamePrefix();
        var cookieName = BffConstants.RefreshCookieName(prefix);
        var cookiePath = _resolver.GetCookiePath();
        var xsrfCookieName = BffConstants.XsrfCookieName(prefix);

        if (!ctx.Request.Cookies.ContainsKey(cookieName))
        {
            return;
        }

        var parked = _refreshStore.Read(ctx, cookieName);
        if (parked is null)
        {
            // Present but undecryptable (wrong key ring / tampered) — garbage, drop it.
            _refreshStore.Delete(ctx, cookieName, cookiePath);
            return;
        }

        var outcome = await _renewer.TryRenewAsync(
            ctx, parked, cookieName, cookiePath, xsrfCookieName, ctx.RequestAborted);

        // Rejected = the refresh token was definitively refused (invalid_grant, revoked).
        // Transient failures keep the parked cookie — the next request retries.
        if (outcome == BffRenewOutcome.Rejected)
        {
            _refreshStore.Delete(ctx, cookieName, cookiePath);
        }
    }

    private async Task HandleLoginAsync(HttpContext ctx)
    {
        var returnUrl = BffUrlGuard.SanitizeReturnUrl(ctx.Request.Query["returnUrl"].ToString());

        var redirectCtx = new BffRedirectContext(ctx, returnUrl);
        await _handler.OnLoginRedirectingAsync(redirectCtx);

        // The hook may have adjusted the return URL — sanitize again; it drives a redirect.
        returnUrl = BffUrlGuard.SanitizeReturnUrl(redirectCtx.ReturnUrl);
        ctx.Items[ExtraParametersItemKey] = redirectCtx.ExtraParameters;

        // ChallengeAsync → OIDC handler generates state + PKCE + correlation cookie and
        // 302s to /authorize. The validated returnUrl rides in AuthenticationProperties.
        // RedirectUri and becomes the post-callback landing page.
        await ctx.ChallengeAsync(BffConstants.OidcScheme, new AuthenticationProperties
        {
            RedirectUri = returnUrl
        });
    }

    private async Task HandleLogoutAsync(HttpContext ctx)
    {
        var returnUrl = BffUrlGuard.SanitizeReturnUrl(ctx.Request.Query["returnUrl"].ToString());

        var logoutCtx = new BffLogoutContext(ctx, ctx.User, returnUrl);
        await _handler.OnLogoutAsync(logoutCtx);
        returnUrl = BffUrlGuard.SanitizeReturnUrl(logoutCtx.ReturnUrl);

        await ctx.SignOutAsync(BffConstants.SessionScheme);

        // Parked refresh goes too (Stage 4's XSRF cookie is deleted as well — expiring a
        // cookie that was never set is harmless).
        var prefix = _resolver.GetCookieNamePrefix();
        var path = _resolver.GetCookiePath();
        _refreshStore.Delete(ctx, BffConstants.RefreshCookieName(prefix), path);
        ExpireCookie(ctx, BffConstants.XsrfCookieName(prefix), path);

        ctx.Response.Redirect(returnUrl);
    }

    private static void ExpireCookie(HttpContext ctx, string name, string path)
    {
        ctx.Response.Cookies.Append(name, string.Empty, new CookieOptions
        {
            Path = path,
            Expires = DateTimeOffset.UnixEpoch,
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = ctx.Request.IsHttps
        });
    }
}
