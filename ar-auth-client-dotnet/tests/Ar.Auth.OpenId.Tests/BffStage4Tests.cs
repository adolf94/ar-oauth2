using System.Net;
using Ar.Auth.OpenId.AspNetCore;

namespace Ar.Auth.OpenId.Tests;

/// <summary>
/// Stage 4 (docs/bff-implementation-plan.md): the signed double-submit CSRF layer —
/// XSRF-TOKEN cookie issuance at session establishment/renewal, enforcement on unsafe
/// cookie-authenticated requests, exemptions (safe methods, Bearer, Csrf=Off), and the
/// cookie-tossing guard (design doc §4, layer 3).
/// </summary>
public class BffStage4Tests
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

    private static async Task CompleteLoginAsync(TestClient tc, BffTestApp app)
    {
        var login = await tc.Http.GetAsync(app.BaseUrl + "/auth/login?returnUrl=/dashboard");
        Assert.Equal(HttpStatusCode.Found, login.StatusCode);

        var authorize = await tc.Http.GetAsync(login.Headers.Location!);
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);

        var callback = await tc.Http.GetAsync(authorize.Headers.Location!);
        Assert.Equal(HttpStatusCode.Found, callback.StatusCode);
    }

    // ── T4.1: issuance ───────────────────────────────────────────────────────

    [Fact]
    public async Task Callback_issues_readable_signed_xsrf_cookie()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();
        var appUri = new Uri(app.BaseUrl);

        var login = await tc.Http.GetAsync(app.BaseUrl + "/auth/login");
        var authorize = await tc.Http.GetAsync(login.Headers.Location!);
        var callback = await tc.Http.GetAsync(authorize.Headers.Location!);

        // Non-HttpOnly by design — the SPA must read it (this is the ONLY cookie it may read).
        var setCookies = string.Join("\n", callback.Headers.GetValues("Set-Cookie"));
        var xsrfCookie = setCookies.Split('\n').FirstOrDefault(c => c.StartsWith("XSRF-TOKEN="));
        Assert.NotNull(xsrfCookie);
        Assert.DoesNotContain("HttpOnly", xsrfCookie);

        var cookie = GetCookie(tc, appUri, BffConstants.XsrfCookieName(string.Empty));
        Assert.NotNull(cookie);
        Assert.False(cookie!.HttpOnly);

        // Silent renewal also re-issues the XSRF cookie with the fresh session.
        var clone = new TestClient();
        var parked = GetCookie(tc, appUri, BffConstants.RefreshCookieName(string.Empty));
        Assert.NotNull(parked);
        clone.Cookies.Add(appUri, new Cookie(parked!.Name, parked.Value, parked.Path));
        var me = await clone.Http.GetAsync(app.BaseUrl + "/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.NotNull(GetCookie(clone, appUri, BffConstants.XsrfCookieName(string.Empty)));
    }

    // ── T4.2: enforcement ─────────────────────────────────────────────────────

    [Fact]
    public async Task Unsafe_post_without_csrf_header_is_forbidden()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();

        await CompleteLoginAsync(tc, app);

        // Cookie-authenticated (the session cookie rides automatically) but no header.
        var res = await tc.Http.PostAsync(app.BaseUrl + "/submit", content: null);
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
    }

    [Fact]
    public async Task Unsafe_post_with_mismatched_header_is_forbidden()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();

        await CompleteLoginAsync(tc, app);

        var req = new HttpRequestMessage(HttpMethod.Post, app.BaseUrl + "/submit");
        req.Headers.Add(BffConstants.CsrfHeaderName, "not-the-cookie-value");
        var res = await tc.Http.SendAsync(req);
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
    }

    [Fact]
    public async Task Unsafe_post_with_matching_header_is_accepted()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();
        var appUri = new Uri(app.BaseUrl);

        await CompleteLoginAsync(tc, app);

        // The SPA wrapper: read XSRF-TOKEN (the only readable cookie) → echo it.
        var xsrf = GetCookie(tc, appUri, BffConstants.XsrfCookieName(string.Empty))!.Value;
        var req = new HttpRequestMessage(HttpMethod.Post, app.BaseUrl + "/submit");
        req.Headers.Add(BffConstants.CsrfHeaderName, xsrf);
        var res = await tc.Http.SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal("accepted", await res.Content.ReadAsStringAsync());
    }

    // ── Exemptions ───────────────────────────────────────────────────────────

    [Fact]
    public async Task Safe_methods_are_exempt_from_csrf()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();

        await CompleteLoginAsync(tc, app);

        // GET without any CSRF header works fine (session established).
        var me = await tc.Http.GetAsync(app.BaseUrl + "/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
    }

    [Fact]
    public async Task Bearer_requests_are_exempt_and_get_401_not_403()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();

        // No session at all, Bearer header present: the CSRF layer never engages —
        // 401 from [Authorize], never a 403.
        var req = new HttpRequestMessage(HttpMethod.Post, app.BaseUrl + "/submit");
        req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Bearer", "some-access-token");
        var res = await tc.Http.SendAsync(req);

        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    // ── T4.3: option gate ─────────────────────────────────────────────────────

    [Fact]
    public async Task Csrf_off_disables_enforcement()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority, bff =>
        {
            bff.Csrf = BffCsrfMode.Off;
        });
        using var tc = new TestClient();
        var appUri = new Uri(app.BaseUrl);

        await CompleteLoginAsync(tc, app);

        // No XSRF cookie issued…
        Assert.Null(GetCookie(tc, appUri, BffConstants.XsrfCookieName(string.Empty)));

        // …and unsafe requests pass without a header (layers 1–2 still protect).
        var res = await tc.Http.PostAsync(app.BaseUrl + "/submit", content: null);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal("accepted", await res.Content.ReadAsStringAsync());
    }

    // ── Cookie-tossing guard (the reason the token is SIGNED) ─────────────────

    [Fact]
    public async Task Tossed_xsrf_cookie_with_matching_header_is_still_rejected()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();
        var appUri = new Uri(app.BaseUrl);

        await CompleteLoginAsync(tc, app);

        // Simulate evil.adolfrey.com planting a Domain=.adolfrey.com cookie: the attacker
        // chooses a value, the SPA echoes it dutifully — double-submit MATCHES — but the
        // value carries no valid signature, so enforcement rejects it.
        var tossed = "attacker-chosen-value";
        tc.Cookies.Add(appUri, new Cookie(BffConstants.XsrfCookieName(string.Empty), tossed, "/"));

        var req = new HttpRequestMessage(HttpMethod.Post, app.BaseUrl + "/submit");
        req.Headers.Add(BffConstants.CsrfHeaderName, tossed);
        var res = await tc.Http.SendAsync(req);

        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
    }
}
