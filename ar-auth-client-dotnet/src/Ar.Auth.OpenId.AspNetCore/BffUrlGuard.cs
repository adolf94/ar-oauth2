namespace Ar.Auth.OpenId.AspNetCore;

/// <summary>
/// Return-URL sanitization: only root-relative local paths are ever honored. Absolute or
/// scheme-carrying values fall back to "/" — the open-redirect guard of the login flow
/// (design doc §3.6).
/// </summary>
internal static class BffUrlGuard
{
    /// <summary>
    /// Returns a safe local return URL. Null/empty → "/"; anything that is not a plain
    /// root-relative path (absolute URLs, protocol-relative "//", colon smuggles) → "/".
    /// </summary>
    public static string SanitizeReturnUrl(string? url)
    {
        if (string.IsNullOrEmpty(url))
        {
            return "/";
        }

        if (!url.StartsWith('/') || url.StartsWith("//"))
        {
            return "/";
        }

        // Conservative: a colon in a root-relative path is virtually always a scheme
        // smuggle (e.g. "/https://evil" or "/x:8080@evil"); reject the whole URL.
        if (url.Contains(':'))
        {
            return "/";
        }

        return url;
    }
}
