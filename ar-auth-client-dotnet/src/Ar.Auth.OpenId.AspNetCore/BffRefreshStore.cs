using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;

namespace Ar.Auth.OpenId.AspNetCore;

/// <summary>
/// Encrypted parking for the refresh token (design doc §3.5): DataProtection-protected
/// HttpOnly cookie, separate name from the session cookie, same app-local path. The
/// browser holds an opaque blob; only the app's key ring can reveal the token inside.
/// </summary>
public sealed class BffRefreshStore
{
    private const string Purpose = "Ar.Auth.OpenId.AspNetCore.Bff.Refresh.v1";

    private readonly IDataProtector _protector;

    public BffRefreshStore(IDataProtectionProvider provider)
        => _protector = provider.CreateProtector(Purpose);

    /// <summary>Parks the refresh token in its encrypted HttpOnly cookie.</summary>
    public void Park(HttpContext ctx, string refreshToken, string cookieName, string path)
    {
        var payload = _protector.Protect(refreshToken);
        ctx.Response.Cookies.Append(cookieName, payload, new CookieOptions
        {
            Path = path,
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = ctx.Request.IsHttps,
            Expires = DateTimeOffset.UtcNow.AddDays(30),
            IsEssential = true
        });
    }

    /// <summary>Reads and decrypts the parked token; null when absent or undecryptable.</summary>
    public string? Read(HttpContext ctx, string cookieName)
    {
        if (!ctx.Request.Cookies.TryGetValue(cookieName, out var value) || string.IsNullOrEmpty(value))
        {
            return null;
        }

        try
        {
            return _protector.Unprotect(value);
        }
        catch
        {
            // Wrong key ring or a tampered value — the caller treats it as garbage.
            return null;
        }
    }

    /// <summary>Deletes the parked cookie (logout, revoked refresh, garbage value).</summary>
    public void Delete(HttpContext ctx, string cookieName, string path)
    {
        ctx.Response.Cookies.Append(cookieName, string.Empty, new CookieOptions
        {
            Path = path,
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = ctx.Request.IsHttps,
            Expires = DateTimeOffset.UnixEpoch,
            IsEssential = true
        });
    }
}
