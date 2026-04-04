using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using backend.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.IdentityModel.Tokens.Jwt;

namespace backend.Endpoints
{
    public static class AuthHelper
    {
        public static (ClaimsPrincipal? Principal, IActionResult? Result) ValidateAdmin(HttpRequest req, ITokenService tokenService, ILogger logger)
        {
            var (principal, result) = ValidateToken(req, tokenService, logger);
            if (result != null) return (null, result);

            if (principal == null || !principal.FindAll(ClaimTypes.Role).Any(c => c.Value == "admin"))
            {
                logger.LogWarning("User is authenticated but does not have the 'admin' role.");
                return (null, new ForbidResult());
            }

            return (principal, null);
        }

        public static (ClaimsPrincipal? Principal, IActionResult? Result) ValidateToken(HttpRequest req, ITokenService tokenService, ILogger logger)
        {
            if (!req.Headers.TryGetValue("Authorization", out var authHeader))
            {
                return (null, new UnauthorizedObjectResult(new { error = "missing_token" }));
            }

            var authHeaderStr = authHeader.ToString();
            if (string.IsNullOrEmpty(authHeaderStr) || !authHeaderStr.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return (null, new UnauthorizedObjectResult(new { error = "invalid_auth_header" }));
            }

            var token = authHeaderStr.Substring("Bearer ".Length).Trim();
            var principal = tokenService.ValidateAccessToken(token);

            if (principal == null)
            {
                logger.LogWarning("Invalid access token provided.");
                return (null, new UnauthorizedObjectResult(new { error = "invalid_token" }));
            }

            return (principal, null);
        }
        // ── Session Cookie (ar_auth_session) ──

        private const string SessionCookieName = "ar_auth_session";

        public static void SetSessionCookie(HttpResponse res, string sessionToken)
        {
            var options = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax, // Using Lax to survive redirects from apps
                Expires = DateTime.UtcNow.AddDays(30),
                Path = "/"
            };
            res.Cookies.Append(SessionCookieName, sessionToken, options);
        }

        public static string? GetSessionUserId(HttpRequest req, ITokenService tokenService)
        {
            if (req.Cookies.TryGetValue(SessionCookieName, out var token) && !string.IsNullOrEmpty(token))
            {
                var principal = tokenService.ValidateSessionToken(token);
                // Try sub and NameIdentifier as JwtSecurityTokenHandler often maps sub to NameIdentifier
                return principal?.FindFirst(JwtRegisteredClaimNames.Sub)?.Value 
                    ?? principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            }
            return null;
        }

        public static void ClearSessionCookie(HttpResponse res)
        {
            res.Cookies.Delete(SessionCookieName, new CookieOptions
            {
                Path = "/",
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax
            });
        }
    }
}
