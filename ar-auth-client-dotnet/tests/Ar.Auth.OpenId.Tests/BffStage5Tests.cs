using System.Net;
using System.Security.Claims;
using Ar.Auth.OpenId.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Ar.Auth.OpenId.Tests;

/// <summary>
/// Stage 5 (docs/bff-implementation-plan.md): the extensibility surface — hook invocation
/// order, the ArAuthHandler subclass registration with constructor injection, composition
/// of subclass virtuals with BffEvents delegates, reject via subclass, and the
/// renewal/logout hooks (design doc §3.9).
/// </summary>
public class BffStage5Tests
{
    private sealed class TestClient : IDisposable
    {
        public readonly CookieContainer Cookies = new();
        private readonly HttpClientHandler _handler;
        public readonly HttpClient Http;

        public TestClient()
        {
            _handler = new HttpClientHandler
            {
                CookieContainer = Cookies,
                AllowAutoRedirect = false
            };
            Http = new HttpClient(_handler);
        }

        public void Dispose()
        {
            Http.Dispose();
            _handler.Dispose();
        }
    }

    private static Cookie? GetCookie(TestClient tc, Uri uri, string name)
        => tc.Cookies.GetCookies(uri).Cast<Cookie?>().FirstOrDefault(c => c!.Name == name);

    private static async Task CompleteLoginAsync(TestClient tc, BffTestApp app, string loginPath = "/auth/login")
    {
        var login = await tc.Http.GetAsync(app.BaseUrl + loginPath);
        Assert.Equal(HttpStatusCode.Found, login.StatusCode);

        var authorize = await tc.Http.GetAsync(login.Headers.Location!);
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);

        var callback = await tc.Http.GetAsync(authorize.Headers.Location!);
        Assert.Equal(HttpStatusCode.Found, callback.StatusCode);
    }

    // ── T5.4: hook invocation order + login parameterization ─────────────────

    [Fact]
    public async Task Login_hooks_fire_in_order_and_can_parameterize_authorize()
    {
        await using var stub = await StubOidcServer.StartAsync();

        var order = new List<string>();
        await using var app = await BffTestApp.StartAsync(stub.Authority, bff =>
        {
            bff.Events.OnLoginRedirectingAsync = ctx =>
            {
                order.Add("login");
                ctx.ExtraParameters["prompt"] = "login";
                return Task.CompletedTask;
            };
            bff.Events.OnAuthenticatedAsync = ctx =>
            {
                order.Add("authenticated");
                return Task.CompletedTask;
            };
            bff.Events.OnRedirectingAsync = ctx =>
            {
                order.Add("redirecting");
                ctx.ReturnUrl = "/after-login"; // last-chance landing adjustment
                return Task.CompletedTask;
            };
        });

        using var tc = new TestClient();
        var login = await tc.Http.GetAsync(app.BaseUrl + "/auth/login?returnUrl=/dashboard");
        Assert.Equal(HttpStatusCode.Found, login.StatusCode);

        // Login hook's extra parameters ride to /authorize.
        Assert.Contains("prompt=login", login.Headers.Location!.ToString());

        var authorize = await tc.Http.GetAsync(login.Headers.Location!);
        var callback = await tc.Http.GetAsync(authorize.Headers.Location!);

        // All three fired, in pipeline order, across the round trip.
        Assert.Equal(new[] { "login", "authenticated", "redirecting" }, order);

        // The redirecting hook's adjusted (re-sanitized) return URL is where the user lands.
        Assert.Equal("/after-login", callback.Headers.Location!.ToString());
    }

    // ── T5.2/T5.4: subclass registration, DI resolution, composition ──────────

    private sealed class HookRecorder
    {
        public bool SubclassHookRan { get; set; }
    }

    private sealed class RecordingHandler : ArAuthHandler
    {
        public RecordingHandler(BffOptions options, BffPathResolver resolver, HookRecorder recorder)
            : base(options, resolver)
        {
            Recorder = recorder;
        }

        public HookRecorder Recorder { get; }

        public override Task OnAuthenticatedAsync(BffAuthenticatedContext ctx)
        {
            Recorder.SubclassHookRan = true;
            ((ClaimsIdentity)ctx.Principal.Identity!).AddClaim(
                new Claim("subclass-role", "from-subclass"));

            // Compose: base fires the BffEvents delegate of the same name.
            return base.OnAuthenticatedAsync(ctx);
        }
    }

    [Fact]
    public async Task Subclass_resolves_via_DI_and_composes_with_delegate_hooks()
    {
        await using var stub = await StubOidcServer.StartAsync();

        await using var app = await BffTestApp.StartAsync(
            stub.Authority,
            configureServices: s => s.AddSingleton<HookRecorder>(),
            configureAuth: auth => auth.AddArAuthBff<RecordingHandler>(bff =>
            {
                bff.Events.OnAuthenticatedAsync = ctx =>
                {
                    ((ClaimsIdentity)ctx.Principal.Identity!).AddClaim(
                        new Claim("delegate-role", "from-delegate"));
                    return Task.CompletedTask;
                };
            }));

        using var tc = new TestClient();
        await CompleteLoginAsync(tc, app);

        // The subclass was constructed by DI (constructor injection of HookRecorder)…
        var recorder = app.GetService<HookRecorder>();
        Assert.True(recorder.SubclassHookRan);

        // …its enrichment AND the delegate's both landed in the session (composition).
        var claims = await tc.Http.GetStringAsync(app.BaseUrl + "/claims");
        Assert.Contains("from-subclass", claims);
        Assert.Contains("from-delegate", claims);
        Assert.Contains("user-42", claims);
    }

    private sealed class RejectingHandler : ArAuthHandler
    {
        public RejectingHandler(BffOptions options, BffPathResolver resolver)
            : base(options, resolver)
        {
        }

        public override Task OnAuthenticatedAsync(BffAuthenticatedContext ctx)
        {
            ctx.Reject("blocked by subclass policy");
            return Task.CompletedTask; // no base call — the delegate is skipped too
        }
    }

    [Fact]
    public async Task Subclass_reject_aborts_login_without_session()
    {
        await using var stub = await StubOidcServer.StartAsync();

        await using var app = await BffTestApp.StartAsync(
            stub.Authority,
            configureAuth: auth => auth.AddArAuthBff<RejectingHandler>());

        using var tc = new TestClient();
        var appUri = new Uri(app.BaseUrl);

        var login = await tc.Http.GetAsync(app.BaseUrl + "/auth/login");
        var authorize = await tc.Http.GetAsync(login.Headers.Location!);
        var callback = await tc.Http.GetAsync(authorize.Headers.Location!);

        // Graceful redirect to login, no session cookie.
        Assert.Equal(HttpStatusCode.Found, callback.StatusCode);
        Assert.Equal("/auth/login", callback.Headers.Location!.ToString());
        Assert.Null(GetCookie(tc, appUri, BffConstants.SessionCookieName(string.Empty)));

        var me = await tc.Http.GetAsync(app.BaseUrl + "/me");
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }

    // ── OnRenewedAsync / OnLogoutAsync ───────────────────────────────────────

    [Fact]
    public async Task Renewal_fires_the_renewed_hook_with_principal()
    {
        await using var stub = await StubOidcServer.StartAsync();

        var renewals = 0;
        string? renewedSub = null;
        await using var app = await BffTestApp.StartAsync(stub.Authority, bff =>
        {
            bff.Events.OnRenewedAsync = ctx =>
            {
                renewals++;
                renewedSub = ctx.Principal.FindFirst("sub")?.Value;
                return Task.CompletedTask;
            };
        });

        using var tc = new TestClient();
        var appUri = new Uri(app.BaseUrl);
        await CompleteLoginAsync(tc, app);

        Assert.Equal(0, renewals); // authenticated requests never renew

        // Session "expires": only the parked refresh remains.
        var parked = GetCookie(tc, appUri, BffConstants.RefreshCookieName(string.Empty));
        using var anon = new TestClient();
        anon.Cookies.Add(appUri, new Cookie(parked!.Name, parked.Value, parked.Path));

        var me = await anon.Http.GetAsync(app.BaseUrl + "/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);

        Assert.Equal(1, renewals);
        Assert.Equal("user-42", renewedSub);
    }

    [Fact]
    public async Task Logout_fires_the_logout_hook_with_principal()
    {
        await using var stub = await StubOidcServer.StartAsync();

        string? loggedOutSub = null;
        await using var app = await BffTestApp.StartAsync(stub.Authority, bff =>
        {
            bff.Events.OnLogoutAsync = ctx =>
            {
                loggedOutSub = ctx.Principal?.FindFirst("sub")?.Value;
                ctx.ReturnUrl = "/after-logout";
                return Task.CompletedTask;
            };
        });

        using var tc = new TestClient();
        await CompleteLoginAsync(tc, app);

        var logout = await tc.Http.GetAsync(app.BaseUrl + "/auth/logout?returnUrl=/bye");
        Assert.Equal(HttpStatusCode.Found, logout.StatusCode);

        // The hook saw the authenticated principal and adjusted the landing URL.
        Assert.Equal("user-42", loggedOutSub);
        Assert.Equal("/after-logout", logout.Headers.Location!.ToString());
    }
}
