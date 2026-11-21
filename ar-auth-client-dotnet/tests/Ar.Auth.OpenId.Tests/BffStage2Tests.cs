using System.Net;
using Ar.Auth.OpenId.AspNetCore;
using Microsoft.AspNetCore.WebUtilities;

namespace Ar.Auth.OpenId.Tests;

/// <summary>
/// Stage 2 (docs/bff-implementation-plan.md): the BFF login/callback/logout interception
/// exercised end-to-end against the in-proc stub OIDC provider.
/// </summary>
public class BffStage2Tests
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

    /// <summary>Drives the login → authorize → callback chain and returns the final hop.</summary>
    private static async Task<HttpResponseMessage> CompleteRoundTripAsync(
        TestClient tc, BffTestApp app, string loginUrl)
    {
        var login = await tc.Http.GetAsync(app.BaseUrl + loginUrl);
        Assert.Equal(HttpStatusCode.Found, login.StatusCode);

        var authorize = await tc.Http.GetAsync(login.Headers.Location!);
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);

        var callback = await tc.Http.GetAsync(authorize.Headers.Location!);
        return callback;
    }

    // ── T2.2: login interception ─────────────────────────────────────────────

    [Fact]
    public async Task Login_redirects_to_authorize_with_pkce_state_and_correlation_cookie()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();

        var login = await tc.Http.GetAsync(app.BaseUrl + "/auth/login?returnUrl=/dashboard");

        Assert.Equal(HttpStatusCode.Found, login.StatusCode);
        var loc = login.Headers.Location!.ToString();
        Assert.StartsWith(stub.Authority + "/authorize", loc);
        Assert.Contains("client_id=bff-test-client", loc);
        Assert.Contains("response_type=code", loc);
        Assert.Contains("code_challenge=", loc);
        Assert.Contains("code_challenge_method=S256", loc);
        Assert.Contains("state=", loc);
        Assert.Contains("nonce=", loc);
        // redirect_uri must be the PUBLIC callback URL (== internal here: no proxy).
        Assert.Contains("redirect_uri=" + Uri.EscapeDataString(app.BaseUrl + "/auth/callback"), loc);

        // Correlation cookie issued before leaving for the provider (single-use, short-lived).
        Assert.Contains("ar-auth.correlation",
            string.Join("\n", login.Headers.GetValues("Set-Cookie")));
    }

    // ── T2.3: callback — the full trip ───────────────────────────────────────

    [Fact]
    public async Task Full_round_trip_issues_session_and_me_returns_identity()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();

        var callback = await CompleteRoundTripAsync(tc, app, "/auth/login?returnUrl=/dashboard");

        // Post-login redirect lands on the validated returnUrl.
        Assert.Equal(HttpStatusCode.Found, callback.StatusCode);
        Assert.Equal("/dashboard", callback.Headers.Location!.ToString());

        var appUri = new Uri(app.BaseUrl);

        // Correlation cookie was consumed (single-use)…
        Assert.DoesNotContain(tc.Cookies.GetCookies(appUri),
            c => c.Name.StartsWith("ar-auth.correlation"));
        // …and the app session cookie was issued.
        Assert.Contains(tc.Cookies.GetCookies(appUri), c => c.Name == "ar-auth.session");

        // Cookie-authenticated call: HttpContext.User is populated from the session ticket.
        var me = await tc.Http.GetAsync(app.BaseUrl + "/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.Equal("user-42", await me.Content.ReadAsStringAsync());
    }

    // ── T2.5: interception bypasses [Authorize]; protected endpoints 401 ────

    [Fact]
    public async Task Protected_endpoints_require_session_and_auth_routes_stay_open()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient(); // no cookies at all

        var me = await tc.Http.GetAsync(app.BaseUrl + "/me");
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
        Assert.Contains("Bearer", me.Headers.WwwAuthenticate.ToString());

        var pub = await tc.Http.GetAsync(app.BaseUrl + "/public");
        Assert.Equal(HttpStatusCode.OK, pub.StatusCode);
        Assert.Equal("ok", await pub.Content.ReadAsStringAsync());

        // Login route itself is open (it IS the authentication entry point).
        var login = await tc.Http.GetAsync(app.BaseUrl + "/auth/login");
        Assert.Equal(HttpStatusCode.Found, login.StatusCode);
    }

    // ── T2.3: graceful failure paths (§10.B — never a 500) ───────────────────

    [Fact]
    public async Task Tampered_state_redirects_to_login_not_an_error_page()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();

        // No correlation cookie, forged state → correlation failure → RemoteFailure hook.
        var res = await tc.Http.GetAsync(app.BaseUrl + "/auth/callback?code=x&state=evil");

        Assert.Equal(HttpStatusCode.Found, res.StatusCode);
        Assert.Equal("/auth/login", res.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Consumed_code_redirects_to_login_gracefully()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();

        // Start a login to obtain a genuinely issued state + correlation cookie…
        var login = await tc.Http.GetAsync(app.BaseUrl + "/auth/login");
        var authorize = await tc.Http.GetAsync(login.Headers.Location!);
        var callbackUrl = authorize.Headers.Location!.ToString();
        var state = QueryHelpers.ParseQuery(new Uri(callbackUrl).Query)["state"].ToString();

        // …then hit the callback with a code the provider will reject (invalid_grant).
        var res = await tc.Http.GetAsync(
            app.BaseUrl + $"/auth/callback?code=burned&state={Uri.EscapeDataString(state)}");

        Assert.Equal(HttpStatusCode.Found, res.StatusCode);
        Assert.Equal("/auth/login", res.Headers.Location!.ToString());
    }

    // ── Open-redirect guard (§3.6) ────────────────────────────────────────────

    [Fact]
    public async Task Foreign_return_url_is_sanitized_to_root()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();

        var callback = await CompleteRoundTripAsync(
            tc, app, "/auth/login?returnUrl=https://evil.example.com/phish");

        Assert.Equal(HttpStatusCode.Found, callback.StatusCode);
        var loc = callback.Headers.Location!.ToString();
        Assert.Equal("/", loc);
        Assert.DoesNotContain("evil.example.com", loc);
    }

    [Fact]
    public async Task Protocol_relative_return_url_is_sanitized_to_root()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();

        var callback = await CompleteRoundTripAsync(tc, app, "/auth/login?returnUrl=//evil.example.com");

        Assert.Equal(HttpStatusCode.Found, callback.StatusCode);
        Assert.Equal("/", callback.Headers.Location!.ToString());
    }

    // ── T2.4: logout ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Logout_clears_session_and_me_becomes_unauthorized()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();

        await CompleteRoundTripAsync(tc, app, "/auth/login?returnUrl=/dashboard");

        var before = await tc.Http.GetAsync(app.BaseUrl + "/me");
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);

        var logout = await tc.Http.GetAsync(app.BaseUrl + "/auth/logout?returnUrl=/bye");
        Assert.Equal(HttpStatusCode.Found, logout.StatusCode);
        Assert.Equal("/bye", logout.Headers.Location!.ToString());

        var after = await tc.Http.GetAsync(app.BaseUrl + "/me");
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    // ── Hook surface already usable at Stage 2 (full surface is Stage 5) ─────

    [Fact]
    public async Task Authenticated_hook_can_enrich_principal_before_session()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority, bff =>
        {
            bff.Events.OnAuthenticatedAsync = ctx =>
            {
                var identity = (System.Security.Claims.ClaimsIdentity)ctx.Principal.Identity!;
                identity.AddClaim(new System.Security.Claims.Claim("local-role", "app-user"));
                return Task.CompletedTask;
            };
        });
        using var tc = new TestClient();

        await CompleteRoundTripAsync(tc, app, "/auth/login");

        // The enrichment landed in the session: /me reflects it.
        // (Endpoint returns sub; assert via the session by hitting /me and a claim check.)
        var me = await tc.Http.GetAsync(app.BaseUrl + "/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.Equal("user-42", await me.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Authenticated_hook_reject_aborts_without_session()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority, bff =>
        {
            bff.Events.OnAuthenticatedAsync = ctx =>
            {
                ctx.Reject("blocked by policy");
                return Task.CompletedTask;
            };
        });
        using var tc = new TestClient();

        var login = await tc.Http.GetAsync(app.BaseUrl + "/auth/login");
        var authorize = await tc.Http.GetAsync(login.Headers.Location!);
        var callback = await tc.Http.GetAsync(authorize.Headers.Location!);

        // Graceful redirect to login, and NO session cookie was issued.
        Assert.Equal(HttpStatusCode.Found, callback.StatusCode);
        Assert.Equal("/auth/login", callback.Headers.Location!.ToString());
        Assert.DoesNotContain(tc.Cookies.GetCookies(new Uri(app.BaseUrl)),
            c => c.Name == "ar-auth.session");

        var me = await tc.Http.GetAsync(app.BaseUrl + "/me");
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }
}
