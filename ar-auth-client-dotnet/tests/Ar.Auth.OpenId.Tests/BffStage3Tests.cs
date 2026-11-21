using System.Net;
using Ar.Auth.OpenId.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;

namespace Ar.Auth.OpenId.Tests;

/// <summary>
/// Stage 3 (docs/bff-implementation-plan.md): refresh parking at the callback, single-flight
/// silent renewal from the parked cookie, and the rejection/cleanup paths. The stub burns
/// refresh tokens on use (rotation), exactly like the ar-auth server (design doc §10.A).
/// </summary>
public class BffStage3Tests
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
        Assert.Equal("/dashboard", callback.Headers.Location!.ToString());
    }

    /// <summary>A fresh client holding ONLY the parked refresh cookie — session "expired".</summary>
    private static TestClient CloneWithParkedOnly(TestClient source, Uri appUri)
    {
        var clone = new TestClient();
        var parked = GetCookie(source, appUri, BffConstants.RefreshCookieName(string.Empty));
        Assert.NotNull(parked); // precondition: the round trip parked a token
        clone.Cookies.Add(appUri, new Cookie(parked!.Name, parked.Value, parked.Path));
        return clone;
    }

    // ── T3.2: refresh parking at the callback ────────────────────────────────

    [Fact]
    public async Task Callback_parks_refresh_token_and_strips_tokens_from_session_ticket()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();
        var appUri = new Uri(app.BaseUrl);

        await CompleteLoginAsync(tc, app);

        // Parked in its own cookie, encrypted (no raw token text in the browser jar).
        var parked = GetCookie(tc, appUri, BffConstants.RefreshCookieName(string.Empty));
        Assert.NotNull(parked);
        Assert.DoesNotContain("stub-refresh", parked!.Value);

        // Nothing token-ish inside the session ticket either: unprotect it with the
        // app's own ticket format and inspect the properties.
        var sessionValue = GetCookie(tc, appUri, BffConstants.SessionCookieName(string.Empty));
        Assert.NotNull(sessionValue);
        var cookieOptions = app
            .GetService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(BffConstants.SessionScheme);
        var ticket = cookieOptions.TicketDataFormat.Unprotect(sessionValue!.Value);
        Assert.NotNull(ticket);
        Assert.Null(ticket!.Properties.GetTokenValue("refresh_token"));
        Assert.Null(ticket.Properties.GetTokenValue("access_token"));
        Assert.Equal("user-42", ticket.Principal.FindFirst("sub")?.Value);

        // A normal authenticated request never triggers renewal.
        var me = await tc.Http.GetAsync(app.BaseUrl + "/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.Equal(0, stub.RefreshGrantCount);
    }

    // ── T3.3: silent renewal ──────────────────────────────────────────────────

    [Fact]
    public async Task Expired_session_is_silently_renewed_from_parked_refresh()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();
        var appUri = new Uri(app.BaseUrl);

        await CompleteLoginAsync(tc, app);
        var parkedBefore = GetCookie(tc, appUri, BffConstants.RefreshCookieName(string.Empty))!.Value;

        // The session cookie is gone (expired); only the parked refresh remains.
        using var anon = CloneWithParkedOnly(tc, appUri);

        var me = await anon.Http.GetAsync(app.BaseUrl + "/me");

        // Invisible renewal: the request succeeds without any login redirect.
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.Equal("user-42", await me.Content.ReadAsStringAsync());
        Assert.Equal(1, stub.RefreshGrantCount);

        // New session + rotated parked refresh were issued.
        Assert.NotNull(GetCookie(anon, appUri, BffConstants.SessionCookieName(string.Empty)));
        var parkedAfter = GetCookie(anon, appUri, BffConstants.RefreshCookieName(string.Empty));
        Assert.NotNull(parkedAfter);
        Assert.NotEqual(parkedBefore, parkedAfter!.Value);
    }

    [Fact]
    public async Task Concurrent_expired_requests_renew_exactly_once()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();
        var appUri = new Uri(app.BaseUrl);

        await CompleteLoginAsync(tc, app);

        // Five parallel "tabs", each carrying the same (about-to-be-consumed) token —
        // the one-time-use rotation means a naive implementation burns the token on 4
        // of them and spuriously logs the user out (design doc §10.A).
        var clients = Enumerable.Range(0, 5)
            .Select(_ => CloneWithParkedOnly(tc, appUri))
            .ToList();
        try
        {
            var responses = await Task.WhenAll(
                clients.Select(c => c.Http.GetAsync(app.BaseUrl + "/me")));

            Assert.All(responses, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
            foreach (var r in responses)
            {
                Assert.Equal("user-42", await r.Content.ReadAsStringAsync());
            }

            // Single-flight: exactly one refresh_token round-trip at the auth server.
            Assert.Equal(1, stub.RefreshGrantCount);
        }
        finally
        {
            foreach (var c in clients)
            {
                c.Dispose();
            }
        }
    }

    // ── T3.3: rejection + cleanup ────────────────────────────────────────────

    [Fact]
    public async Task Revoked_refresh_falls_through_to_401_and_deletes_parked_cookie()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();
        var appUri = new Uri(app.BaseUrl);

        await CompleteLoginAsync(tc, app);

        // Server-side revocation (session terminated upstream).
        stub.RevokeAllRefreshTokens();

        using var anon = CloneWithParkedOnly(tc, appUri);
        var me = await anon.Http.GetAsync(app.BaseUrl + "/me");

        // Graceful: plain 401 (the SPA shows the login link), parked cookie deleted.
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
        Assert.Equal(1, stub.RefreshGrantCount); // one failed attempt, then cleanup

        // CookieContainer processed the expired Set-Cookie — nothing remains parked.
        Assert.Null(GetCookie(anon, appUri, BffConstants.RefreshCookieName(string.Empty)));
        Assert.Null(GetCookie(anon, appUri, BffConstants.SessionCookieName(string.Empty)));
    }

    [Fact]
    public async Task Logout_deletes_parked_refresh_cookie()
    {
        await using var stub = await StubOidcServer.StartAsync();
        await using var app = await BffTestApp.StartAsync(stub.Authority);
        using var tc = new TestClient();
        var appUri = new Uri(app.BaseUrl);

        await CompleteLoginAsync(tc, app);
        Assert.NotNull(GetCookie(tc, appUri, BffConstants.RefreshCookieName(string.Empty)));

        var logout = await tc.Http.GetAsync(app.BaseUrl + "/auth/logout?returnUrl=/bye");
        Assert.Equal(HttpStatusCode.Found, logout.StatusCode);

        Assert.Null(GetCookie(tc, appUri, BffConstants.SessionCookieName(string.Empty)));
        Assert.Null(GetCookie(tc, appUri, BffConstants.RefreshCookieName(string.Empty)));
    }
}
