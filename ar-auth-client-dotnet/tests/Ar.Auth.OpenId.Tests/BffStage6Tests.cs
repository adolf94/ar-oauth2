using System.Net;
using System.Security.Claims;
using Ar.Auth.OpenId.AspNetCore;

namespace Ar.Auth.OpenId.Tests;

/// <summary>
/// Stage 6 (docs/bff-implementation-plan.md): scheme composition. When the BFF is on,
/// the policy scheme is the default authenticate scheme and picks the credential per
/// request: Bearer header → app session cookie → (optional) auth-server session cookie.
/// Challenge stays JWT-bearer. Precedence per T6.2.
/// </summary>
public class BffStage6Tests
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

    private static async Task CompleteLoginAsync(TestClient tc, BffTestApp app)
    {
        var login = await tc.Http.GetAsync(app.BaseUrl + "/auth/login");
        Assert.Equal(HttpStatusCode.Found, login.StatusCode);

        var authorize = await tc.Http.GetAsync(login.Headers.Location!);
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);

        var callback = await tc.Http.GetAsync(authorize.Headers.Location!);
        Assert.Equal(HttpStatusCode.Found, callback.StatusCode);
    }

    private static async Task<string> GetClaimsAsync(HttpClient http, string baseUrl)
        => await (await http.GetAsync(baseUrl + "/claims")).Content.ReadAsStringAsync();

    // ── T6.2: Bearer header wins over a valid app session cookie ──────────────

    [Fact]
    public async Task Bearer_header_wins_over_valid_app_session_cookie()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);

        using var tc = new TestClient();
        await CompleteLoginAsync(tc, app); // session cookie: sub=user-42

        // Same client, now ALSO carrying a Bearer token for a different identity.
        tc.Http.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", stub.CreateAccessToken("user-77"));

        var claims = await GetClaimsAsync(tc.Http, app.BaseUrl);
        Assert.Contains("user-77", claims); // the Bearer identity was used…
        Assert.DoesNotContain("user-42", claims); // …not the cookie identity.
    }

    // ── T6.2: session cookie authenticates with no header; neither → 401 ─────

    [Fact]
    public async Task App_session_cookie_authenticates_without_bearer_header()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);

        using var tc = new TestClient();
        await CompleteLoginAsync(tc, app);

        var me = await tc.Http.GetAsync(app.BaseUrl + "/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.Equal("user-42", await me.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task No_credential_at_all_yields_401()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);

        using var tc = new TestClient();
        var me = await tc.Http.GetAsync(app.BaseUrl + "/me");
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);

        // The SPA's boot probe contract: challenges advertise Bearer.
        Assert.Contains("Bearer",
            string.Join("\n", me.Headers.WwwAuthenticate.Select(h => h.ToString())));
    }

    // ── T6.1: optional auth-server cookie still works with the BFF on ───────

    [Fact]
    public async Task Auth_server_session_cookie_still_authenticates_when_bff_on()
    {
        await using var stub = await StubOidcServer.StartAsync();

        // BFF on AND the legacy shared-cookie flow enabled.
        await using var app = await BffTestApp.StartAsync(
            stub.Authority,
            configureArAuth: o =>
            {
                o.AllowSessionCookie = true;
                o.CookieName = "srv-session";
            });

        var appUri = new Uri(app.BaseUrl);

        // A user with only the auth-server's session cookie (no app cookie, no parked
        // refresh — e.g. logged in on a sibling app sharing the Domain cookie).
        using var tc = new TestClient();
        tc.Cookies.Add(appUri, new Cookie("srv-session", stub.CreateSessionToken("user-99"), "/"));

        var claims = await GetClaimsAsync(tc.Http, app.BaseUrl);
        Assert.Contains("user-99", claims);

        // Bearer still wins over the server cookie for the same client.
        tc.Http.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", stub.CreateAccessToken("user-77"));
        claims = await GetClaimsAsync(tc.Http, app.BaseUrl);
        Assert.Contains("user-77", claims);
        Assert.DoesNotContain("user-99", claims);
    }
}
