namespace Ar.Auth.OpenId;

/// <summary>
/// CSRF guard for session-cookie authentication.
///
/// Browsers attach cookies automatically, so any page able to make the user's browser issue
/// a request could otherwise ride the session. Requests authenticated by an explicit Bearer
/// header are immune (attacker JavaScript cannot set that header cross-site) and never
/// consult this guard.
/// </summary>
public static class SessionCookieGuard
{
    /// <summary>
    /// Returns true when a request may authenticate via the session cookie.
    /// </summary>
    /// <param name="httpMethod">The HTTP method of the request.</param>
    /// <param name="origin">The request's Origin header, if any.</param>
    /// <param name="referer">The request's Referer header, if any (fallback when Origin is absent).</param>
    /// <param name="requestOrigin">The request's own origin (scheme://host[:port]).</param>
    /// <param name="allowedOrigins">Additional origins allowed to use the cookie cross-origin.</param>
    /// <remarks>
    /// Browsers always send Origin on unsafe methods (POST/PUT/PATCH/DELETE), so a missing
    /// Origin on an unsafe method is rejected. On safe methods (GET/HEAD/OPTIONS) browsers
    /// may legitimately omit Origin, so absence is treated as same-origin.
    /// </remarks>
    public static bool IsOriginAllowed(
        string httpMethod,
        string? origin,
        string? referer,
        string requestOrigin,
        IEnumerable<string>? allowedOrigins)
    {
        var safeMethod = httpMethod.Equals("GET", StringComparison.OrdinalIgnoreCase)
                         || httpMethod.Equals("HEAD", StringComparison.OrdinalIgnoreCase)
                         || httpMethod.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase);

        var candidate = origin;
        if (string.IsNullOrEmpty(candidate) && !string.IsNullOrEmpty(referer))
        {
            candidate = ExtractOrigin(referer);
        }

        if (string.IsNullOrEmpty(candidate))
        {
            return safeMethod;
        }

        if (candidate.Equals(requestOrigin, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return allowedOrigins?.Any(a =>
            a.TrimEnd('/').Equals(candidate.TrimEnd('/'), StringComparison.OrdinalIgnoreCase)) == true;
    }

    /// <summary>
    /// Extracts scheme://host[:port] from an absolute URL, or null when parsing fails.
    /// </summary>
    public static string? ExtractOrigin(string url)
    {
        // Uri.GetLeftPart(Authority) normalizes to lowercase and trims the default port.
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
            (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
        {
            return uri.GetLeftPart(UriPartial.Authority);
        }

        return null;
    }
}
