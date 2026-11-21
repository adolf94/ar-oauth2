using Microsoft.AspNetCore.Http;

namespace Ar.Auth.OpenId.AspNetCore;

/// <summary>
/// Resolves the duality between the INTERNAL path the app's pipeline responds on (after a
/// reverse proxy strips its prefix — the app sees /auth/callback) and the PUBLIC path the
/// browser and the auth server see (https://apps.adolfrey.com/app/api/auth/callback).
/// Everything the auth server or the browser consumes must use the public identity; only
/// route matching uses the internal one. See docs/cookie-auth-plan.md §3.8.
///
/// Precedence for the public identity:
///   1. explicit <see cref="BffOptions.PublicBaseUrl"/> (proxy strips the prefix silently)
///   2. Request.PathBase (app applied UsePathBase itself — authoritative, since the
///      request path already includes the prefix)
///   3. X-Forwarded-Prefix header (proxy announces it)
///   4. bare request host (no prefix at all)
/// </summary>
public sealed class BffPathResolver
{
    private readonly BffOptions _options;

    public BffPathResolver(BffOptions options)
    {
        Validate(options);
        _options = options;
    }

    /// <summary>
    /// The redirect_uri sent to /authorize. Must exactly match the client's registered
    /// redirect URI — the auth server binds the authorization code to it. Resolved
    /// per request (PublicBaseUrl → PathBase → X-Forwarded-Prefix → bare host).
    /// </summary>
    public string GetRedirectUri(HttpContext ctx)
    {
        var (origin, basePath) = ResolvePublicBase(ctx);
        return $"{origin}{basePath}{_options.CallbackPath}";
    }

    /// <summary>
    /// Browser-visible path prefix for all BFF cookies. STATIC — framework cookie schemes
    /// configure paths once at startup, so this uses only options data:
    /// explicit <see cref="BffOptions.CookiePath"/> → PublicBaseUrl path → "/".
    /// When relying on UsePathBase or X-Forwarded-Prefix for the public identity, set
    /// <see cref="BffOptions.CookiePath"/> explicitly for strict per-app scoping.
    /// </summary>
    public string GetCookiePath()
    {
        if (!string.IsNullOrEmpty(_options.CookiePath))
        {
            return EnsureTrailingSlash(_options.CookiePath);
        }

        if (!string.IsNullOrEmpty(_options.PublicBaseUrl))
        {
            if (!Uri.TryCreate(_options.PublicBaseUrl, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                throw new InvalidOperationException(
                    "BffOptions.PublicBaseUrl must be an absolute http(s) URL, e.g. 'https://apps.adolfrey.com/app/api'.");
            }

            var basePath = uri.AbsolutePath.EndsWith("/")
                ? uri.AbsolutePath.TrimEnd('/')
                : uri.AbsolutePath;

            return string.IsNullOrEmpty(basePath) ? "/" : EnsureTrailingSlash(basePath);
        }

        return "/";
    }

    /// <summary>
    /// Cookie-name prefix keeping multiple apps on one host from colliding: derived from
    /// the effective cookie path ("/application1/" → "application1."; "/app/api/" →
    /// "app-api."; "/" → none). Explicit <see cref="BffOptions.CookieNamePrefix"/> wins.
    /// </summary>
    public string GetCookieNamePrefix()
    {
        if (_options.CookieNamePrefix != null)
        {
            return _options.CookieNamePrefix;
        }

        var segment = SanitizePathSegment(GetCookiePath());
        return segment.Length == 0 ? string.Empty : segment + ".";
    }

    private (string Origin, string BasePath) ResolvePublicBase(HttpContext ctx)
    {
        var req = ctx.Request;

        // 1. Explicit public base — the proxy strips its prefix and tells us nothing.
        if (!string.IsNullOrEmpty(_options.PublicBaseUrl))
        {
            if (!Uri.TryCreate(_options.PublicBaseUrl, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                throw new InvalidOperationException(
                    "BffOptions.PublicBaseUrl must be an absolute http(s) URL, e.g. 'https://apps.adolfrey.com/app/api'.");
            }

            var basePath = uri.AbsolutePath.EndsWith("/")
                ? uri.AbsolutePath.TrimEnd('/')
                : uri.AbsolutePath;

            return ($"{uri.Scheme}://{uri.Authority}", basePath);
        }

        // 2. App applied UsePathBase itself — PathBase is authoritative: the request
        //    path already includes the prefix, so a forwarded header would double it.
        if (req.PathBase.HasValue)
        {
            return ($"{req.Scheme}://{req.Host.Value}", req.PathBase.Value);
        }

        // 3. Proxy announces its prefix via header.
        var forwarded = req.Headers["X-Forwarded-Prefix"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwarded))
        {
            return ($"{req.Scheme}://{req.Host.Value}", "/" + forwarded.Trim('/'));
        }

        // 4. No prefix at all.
        return ($"{req.Scheme}://{req.Host.Value}", string.Empty);
    }

    private static string EnsureTrailingSlash(string path)
    {
        return path.EndsWith('/') ? path : path + "/";
    }

    /// <summary>"/app/api/" → "app-api" (path separators become '-', non-alphanumerics dropped).</summary>
    internal static string SanitizePathSegment(string path)
    {
        var chars = path.Trim('/').Select(c => char.IsLetterOrDigit(c) ? c : '-').ToArray();
        return new string(chars).Trim('-');
    }

    private static void Validate(BffOptions options)
    {
        foreach (var (name, value) in new[]
                 {
                     ("LoginPath", options.LoginPath),
                     ("CallbackPath", options.CallbackPath),
                     ("LogoutPath", options.LogoutPath),
                 })
        {
            if (string.IsNullOrWhiteSpace(value) || !value.StartsWith('/'))
            {
                throw new InvalidOperationException(
                    $"BffOptions.{name} must be a root-relative path starting with '/'.");
            }
        }

        if (options.SessionExpiry <= TimeSpan.Zero)
        {
            throw new InvalidOperationException("BffOptions.SessionExpiry must be positive.");
        }
    }
}
