using Ar.Auth.OpenId;

namespace Ar.Auth.OpenId.Tests;

/// <summary>
/// Tests for the session-cookie CSRF guard. These rules are what prevent attacker pages
/// from riding a user's session cookie; see docs/cookie-auth-plan.md.
/// </summary>
public class SessionCookieGuardTests
{
    private const string RequestOrigin = "https://api.adolfrey.com";
    private static readonly string[] Empty = Array.Empty<string>();

    [Theory]
    [InlineData("GET", null, true)]      // browsers may omit Origin on safe methods
    [InlineData("HEAD", null, true)]
    [InlineData("OPTIONS", null, true)]
    [InlineData("POST", null, false)]    // unsafe methods must carry Origin
    [InlineData("DELETE", null, false)]
    [InlineData("GET", "https://evil.example.com", false)]
    [InlineData("POST", "https://evil.example.com", false)]
    public void UnlistedOriginsAreRejected(string method, string? origin, bool expected)
    {
        var result = SessionCookieGuard.IsOriginAllowed(method, origin, null, RequestOrigin, Empty);
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    [InlineData("DELETE")]
    public void SameOriginIsAlwaysAllowed(string method)
    {
        var result = SessionCookieGuard.IsOriginAllowed(method, RequestOrigin, null, RequestOrigin, Empty);
        Assert.True(result);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    public void AllowListedOriginsAreAllowed(string method)
    {
        var allowed = new[] { "https://app.adolfrey.com", "https://other.example.io/" };
        var result = SessionCookieGuard.IsOriginAllowed(method, "https://app.adolfrey.com", null, RequestOrigin, allowed);
        Assert.True(result);
    }

    [Fact]
    public void TrailingSlashOnAllowedOriginIsIgnored()
    {
        var allowed = new[] { "https://app.adolfrey.com/" };
        var result = SessionCookieGuard.IsOriginAllowed("POST", "https://app.adolfrey.com", null, RequestOrigin, allowed);
        Assert.True(result);
    }

    [Fact]
    public void RefererIsUsedWhenOriginIsMissing()
    {
        // Same-site form posts may omit Origin; Referer carries the same information.
        var result = SessionCookieGuard.IsOriginAllowed(
            "POST", null, "https://app.adolfrey.com/settings", RequestOrigin,
            new[] { "https://app.adolfrey.com" });
        Assert.True(result);
    }

    [Fact]
    public void RefererFromForeignOriginIsRejected()
    {
        var result = SessionCookieGuard.IsOriginAllowed(
            "POST", null, "https://evil.example.com/form", RequestOrigin, Empty);
        Assert.False(result);
    }

    [Fact]
    public void OriginBeatsReferer()
    {
        var result = SessionCookieGuard.IsOriginAllowed(
            "POST", RequestOrigin, "https://evil.example.com/form", RequestOrigin, Empty);
        Assert.True(result);
    }

    [Fact]
    public void SchemeMismatchIsRejected()
    {
        var result = SessionCookieGuard.IsOriginAllowed("POST", "http://api.adolfrey.com", null, RequestOrigin, Empty);
        Assert.False(result);
    }

    [Fact]
    public void PortMismatchIsRejected()
    {
        var result = SessionCookieGuard.IsOriginAllowed("POST", "https://api.adolfrey.com:8443", null, RequestOrigin, Empty);
        Assert.False(result);
    }

    [Fact]
    public void ExtractOriginHandlesWellFormedUrls()
    {
        Assert.Equal("https://app.adolfrey.com", SessionCookieGuard.ExtractOrigin("https://app.adolfrey.com/settings?x=1"));
        Assert.Equal("http://localhost:5174", SessionCookieGuard.ExtractOrigin("http://localhost:5174/path"));
        Assert.Null(SessionCookieGuard.ExtractOrigin("not a url"));
        Assert.Null(SessionCookieGuard.ExtractOrigin("ftp://files.example.com/x"));
    }

    [Fact]
    public void DefaultCookieOptionsMatchTheAuthServer()
    {
        var options = new ArAuthOptions();
        Assert.False(options.AllowSessionCookie);          // opt-in only
        Assert.Equal("ar_auth_session", options.CookieName);
        Assert.Null(options.AllowedCookieOrigins);
    }
}
