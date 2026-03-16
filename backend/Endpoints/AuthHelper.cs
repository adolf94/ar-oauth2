using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using backend.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace backend.Endpoints
{
    public static class AuthHelper
    {
        public static (ClaimsPrincipal? Principal, IActionResult? Result) ValidateAdmin(HttpRequest req, TokenService tokenService, ILogger logger)
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

        public static (ClaimsPrincipal? Principal, IActionResult? Result) ValidateToken(HttpRequest req, TokenService tokenService, ILogger logger)
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
    }
}
