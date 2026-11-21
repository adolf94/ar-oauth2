using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;

namespace Ar.Auth.OpenId.AspNetCore;

/// <summary>
/// Signed double-submit CSRF token (design doc §4, layer 3).
///
/// The cookie value is a DataProtection-signed random blob: the SPA copies it verbatim
/// into the <c>X-CSRF-Token</c> header, and enforcement requires header == cookie AND a
/// valid signature. The signature is what closes cookie tossing — a sibling subdomain can
/// plant a <c>Domain=.adolfrey.com</c> cookie with an attacker-chosen value that the SPA
/// would dutifully echo (double-submit would match!), but it cannot produce a valid
/// signature, so enforcement rejects it. Stateless: no server-side store.
/// </summary>
public sealed class BffCsrfTokenService
{
    private const string Purpose = "Ar.Auth.OpenId.AspNetCore.Bff.Csrf.v1";

    private readonly IDataProtector _protector;

    public BffCsrfTokenService(IDataProtectionProvider provider)
        => _protector = provider.CreateProtector(Purpose);

    /// <summary>
    /// Issues a fresh signed XSRF cookie (readable by JS — that is the point) and returns
    /// its value. Called at session establishment (callback) and at silent renewal.
    /// </summary>
    public string Issue(HttpContext ctx, string cookieName, string path, TimeSpan lifetime)
    {
        var value = _protector.Protect(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));

        ctx.Response.Cookies.Append(cookieName, value, new CookieOptions
        {
            Path = path,
            HttpOnly = false, // the SPA must read this one — by design
            SameSite = SameSiteMode.Lax,
            Secure = ctx.Request.IsHttps,
            Expires = DateTimeOffset.UtcNow.Add(lifetime),
            IsEssential = true
        });

        return value;
    }

    /// <summary>
    /// Double-submit check for an unsafe request: the header must echo the cookie exactly,
    /// and the echoed value must carry a valid signature (cookie-tossing guard).
    /// </summary>
    public bool Validate(string? presentedHeader, string? cookieValue)
    {
        if (string.IsNullOrEmpty(presentedHeader) || string.IsNullOrEmpty(cookieValue))
        {
            return false;
        }

        if (!string.Equals(presentedHeader, cookieValue, StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            return _protector.Unprotect(presentedHeader) is not null;
        }
        catch
        {
            return false; // unsigned/foreign payload — tossed or tampered
        }
    }
}
