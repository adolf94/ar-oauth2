using System;
using System.Security.Claims;
using System.Threading.Tasks;
using backend.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace backend.Endpoints
{
    public class ProfileFunction
    {
        private readonly ILogger<ProfileFunction> _logger;
        private readonly UserService _userService;
        private readonly TokenService _tokenService;

        public ProfileFunction(ILogger<ProfileFunction> logger, UserService userService, TokenService tokenService)
        {
            _logger = logger;
            _userService = userService;
            _tokenService = tokenService;
        }

        [Function("GetProfile")]
        public async Task<IActionResult> GetProfile(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "api/profile")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateToken(req, _tokenService, _logger);
            if (error != null) return error;

            var userId = principal!.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return new UnauthorizedObjectResult(new { error = "invalid_token_claims" });
            }

            var user = await _userService.GetByIdAsync(userId);
            if (user == null)
            {
                return new NotFoundResult();
            }

            return new OkObjectResult(new
            {
                user.Id,
                user.Email,
                user.Roles,
                user.ExternalIdentities
            });
        }
    }
}
