using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using backend.Data;
using backend.Models;
using backend.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace backend.Endpoints
{
    public class UserManagementFunction
    {
        private readonly AppDbContext _dbContext;
        private readonly ITokenService _tokenService;
        private readonly ILogger<UserManagementFunction> _logger;

        public UserManagementFunction(
            AppDbContext dbContext,
            ITokenService tokenService,
            ILogger<UserManagementFunction> logger)
        {
            _dbContext = dbContext;
            _tokenService = tokenService;
            _logger = logger;
        }

        [Function("GetUserById")]
        public async Task<IActionResult> GetUserById(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "api/user/{userId}")] HttpRequest req,
            string userId)
        {
            var principal = Authorize(req, "users:read:all");
            if (principal == null) return new UnauthorizedResult();

            _logger.LogInformation("Management API: Fetching user {UserId}.", userId);
            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
            if (user == null) return new NotFoundResult();

            return new OkObjectResult(user);
        }

        private System.Security.Claims.ClaimsPrincipal? Authorize(HttpRequest req, string requiredScope)
        {
            var authHeader = req.Headers["Authorization"].ToString();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ")) return null;

            var token = authHeader.Substring(7);
            var principal = _tokenService.ValidateAccessToken(token);
            if (principal == null) return null;

            // Check if the token has the required scope
            var scopeClaim = principal.FindFirst("scope")?.Value ?? "";
            var scopes = scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            
            // Standard scope check (either fully qualified or short name)
            if (scopes.Contains($"api://ar-auth-management/{requiredScope}") || scopes.Contains(requiredScope))
            {
                return principal;
            }

            // Also check Roles (TokenService adds client-only scopes to roles)
            if (principal.Claims.Any(c => c.Type == System.Security.Claims.ClaimTypes.Role && (c.Value == requiredScope || c.Value == $"api://ar-auth-management/{requiredScope}")))
            {
                return principal;
            }

            _logger.LogWarning("Management API: Missing required scope {RequiredScope}.", requiredScope);
            return null;
        }
    }
}
