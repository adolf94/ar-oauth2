using System.Security.Claims;
using Ar.Auth.OpenId.AspNetCore;
using Microsoft.AspNetCore.Http;

namespace Ar.Auth.OpenId.Tests;

/// <summary>
/// Stage 1 of the BFF build (docs/bff-implementation-plan.md): options defaults, the
/// path-duality resolver, and the hook context contracts.
/// </summary>
public class BffOptionsTests
{
    [Fact]
    public void DefaultsMatchTheDecidedDesign()
    {
        var options = new BffOptions();

        Assert.Equal("/auth/login", options.LoginPath);
        Assert.Equal("/auth/callback", options.CallbackPath);
        Assert.Equal("/auth/logout", options.LogoutPath);
        Assert.Null(options.PublicBaseUrl);
        Assert.Null(options.CookiePath);
        Assert.Null(options.CookieNamePrefix);
        Assert.Equal(TimeSpan.FromHours(8), options.SessionExpiry);
        Assert.Equal(BffCsrfMode.SignedDoubleSubmit, options.Csrf);
        Assert.NotNull(options.Events);
    }

    [Theory]
    [InlineData("")]
    [InlineData("auth/login")]
    public void InvalidPathsAreRejectedAtResolverConstruction(string badPath)
    {
        var options = new BffOptions { LoginPath = badPath };
        Assert.Throws<InvalidOperationException>(() => new BffPathResolver(options));
    }

    [Fact]
    public void NonPositiveSessionExpiryIsRejected()
    {
        var options = new BffOptions { SessionExpiry = TimeSpan.Zero };
        Assert.Throws<InvalidOperationException>(() => new BffPathResolver(options));
    }
}

public class BffPathResolverTests
{
    private static HttpContext NewContext(string scheme = "https", string host = "apps.adolfrey.com")
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Scheme = scheme;
        ctx.Request.Host = new HostString(host);
        return ctx;
    }

    // ── Case 4: no proxy, no prefix ─────────────────────────────────────────

    [Fact]
    public void BareHostRedirectUriHasNoBasePath()
    {
        var resolver = new BffPathResolver(new BffOptions());
        Assert.Equal("https://apps.adolfrey.com/auth/callback", resolver.GetRedirectUri(NewContext()));
        Assert.Equal("/", resolver.GetCookiePath());
        Assert.Equal(string.Empty, resolver.GetCookieNamePrefix());
    }

    // ── Case 3: app applied UsePathBase itself ──────────────────────────────

    [Fact]
    public void PathBaseBecomesTheRedirectPrefix()
    {
        // Cookie scoping is STATIC (framework schemes configure paths once) — without
        // explicit CookiePath it stays "/"; the per-request prefix still drives redirect_uri.
        var ctx = NewContext();
        ctx.Request.PathBase = new PathString("/app/api");

        var resolver = new BffPathResolver(new BffOptions());

        Assert.Equal("https://apps.adolfrey.com/app/api/auth/callback", resolver.GetRedirectUri(ctx));
        Assert.Equal("/", resolver.GetCookiePath());
        Assert.Equal(string.Empty, resolver.GetCookieNamePrefix());
    }

    // ── Case 2: proxy announces its prefix via header ───────────────────────

    [Fact]
    public void ForwardedPrefixBecomesTheRedirectPrefix()
    {
        var ctx = NewContext();
        ctx.Request.Headers["X-Forwarded-Prefix"] = "/app/api";

        var resolver = new BffPathResolver(new BffOptions());

        Assert.Equal("https://apps.adolfrey.com/app/api/auth/callback", resolver.GetRedirectUri(ctx));
    }

    [Fact]
    public void PathBaseWinsOverForwardedPrefixWhenBothExist()
    {
        // UsePathBase was applied by the app — PathBase is authoritative.
        var ctx = NewContext();
        ctx.Request.PathBase = new PathString("/app/api");
        ctx.Request.Headers["X-Forwarded-Prefix"] = "/other";

        var resolver = new BffPathResolver(new BffOptions());

        Assert.Equal("https://apps.adolfrey.com/app/api/auth/callback", resolver.GetRedirectUri(ctx));
    }

    // ── Case 1: explicit PublicBaseUrl (proxy strips prefix silently) ───────

    [Fact]
    public void PublicBaseUrlDrivesRedirectUriAndIgnoresRequestDetails()
    {
        var ctx = NewContext(scheme: "http", host: "internal-host:8080"); // app-internal view

        var resolver = new BffPathResolver(new BffOptions
        {
            PublicBaseUrl = "https://apps.adolfrey.com/app/api"
        });

        Assert.Equal("https://apps.adolfrey.com/app/api/auth/callback", resolver.GetRedirectUri(ctx));
        Assert.Equal("/app/api/", resolver.GetCookiePath());
        Assert.Equal("app-api.", resolver.GetCookieNamePrefix());
    }

    [Fact]
    public void PublicBaseUrlWithoutPathScopesCookiesToRoot()
    {
        var resolver = new BffPathResolver(new BffOptions
        {
            PublicBaseUrl = "https://apps.adolfrey.com/"
        });

        Assert.Equal("https://apps.adolfrey.com/auth/callback", resolver.GetRedirectUri(NewContext()));
        Assert.Equal("/", resolver.GetCookiePath());
    }

    [Fact]
    public void InvalidPublicBaseUrlFailsFast()
    {
        var resolver = new BffPathResolver(new BffOptions { PublicBaseUrl = "not-a-url" });
        Assert.Throws<InvalidOperationException>(() => resolver.GetRedirectUri(NewContext()));
    }

    // ── Explicit overrides ──────────────────────────────────────────────────

    [Fact]
    public void ExplicitCookiePathWinsOverDerivedBasePath()
    {
        var resolver = new BffPathResolver(new BffOptions { CookiePath = "/application1/" });

        Assert.Equal("/application1/", resolver.GetCookiePath());
        Assert.Equal("application1.", resolver.GetCookieNamePrefix());
    }

    [Fact]
    public void CookiePathWithoutTrailingSlashIsNormalized()
    {
        var resolver = new BffPathResolver(new BffOptions { CookiePath = "/application1" });
        Assert.Equal("/application1/", resolver.GetCookiePath());
    }

    [Fact]
    public void ExplicitCookieNamePrefixWins()
    {
        var resolver = new BffPathResolver(new BffOptions { CookieNamePrefix = "app1." });
        Assert.Equal("app1.", resolver.GetCookieNamePrefix());
    }

    [Fact]
    public void MultiSegmentPathsSanitizeToCookieSafeNames()
    {
        // Path separators become '-', non-alphanumerics drop: "/app/api/" → "app-api."
        var resolver = new BffPathResolver(new BffOptions { CookiePath = "/app/api/" });
        Assert.Equal("app-api.", resolver.GetCookieNamePrefix());

        var root = new BffPathResolver(new BffOptions());
        Assert.Equal(string.Empty, root.GetCookieNamePrefix());
    }
}

public class BffContextTests
{
    [Fact]
    public void AuthenticatedContextRejectMarksAbort()
    {
        var ctx = new BffAuthenticatedContext(
            new DefaultHttpContext(), new ClaimsPrincipal(), "/dashboard");

        Assert.False(ctx.Rejected);
        Assert.Equal("/dashboard", ctx.ReturnUrl);

        ctx.Reject("not allowed");

        Assert.True(ctx.Rejected);
        Assert.Equal("not allowed", ctx.RejectReason);
    }

    [Fact]
    public void RedirectContextCarriesExtraParametersForAuthorize()
    {
        var ctx = new BffRedirectContext(new DefaultHttpContext(), null);
        ctx.ReturnUrl = "/deep/link";
        ctx.ExtraParameters["prompt"] = "login";

        Assert.Equal("/deep/link", ctx.ReturnUrl);
        Assert.Equal("login", ctx.ExtraParameters["prompt"]);
    }

    [Fact]
    public void EventsDefaultToNoOps()
    {
        var events = new BffOptions().Events;

        Assert.True(events.OnLoginRedirectingAsync(new BffRedirectContext(new DefaultHttpContext(), null)).IsCompleted);
        Assert.True(events.OnAuthenticatedAsync(new BffAuthenticatedContext(new DefaultHttpContext(), new ClaimsPrincipal(), null)).IsCompleted);
        Assert.True(events.OnRedirectingAsync(new BffRedirectContext(new DefaultHttpContext(), null)).IsCompleted);
        Assert.True(events.OnLogoutAsync(new BffLogoutContext(new DefaultHttpContext(), null, null)).IsCompleted);
        Assert.True(events.OnRenewedAsync(new BffRenewalContext(new DefaultHttpContext(), new ClaimsPrincipal())).IsCompleted);
    }
}
