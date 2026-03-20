using System;
using System.IO;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using backend.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace backend.Endpoints
{
    public class ProfileAutomateRequest
    {
        public string? Secret { get; set; }
        public string? DeviceName { get; set; }
    }

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
                user.ExternalIdentities,
                user.AutomateDeviceName,
                HasAutomateSecret = !string.IsNullOrEmpty(user.AutomateSecret)
            });
        }

        [Function("UpdateAutomateConfig")]
        public async Task<IActionResult> UpdateAutomateConfig(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "api/profile/automate")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateToken(req, _tokenService, _logger);
            if (error != null) return error;

            var userId = principal!.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return new UnauthorizedObjectResult(new { error = "invalid_token_claims" });
            }

            var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            var updateReq = JsonSerializer.Deserialize<ProfileAutomateRequest>(requestBody, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (updateReq == null)
            {
                return new BadRequestObjectResult(new { error = "invalid_request" });
            }

            var success = await _userService.UpdateAutomateSettingsAsync(userId, updateReq.Secret, updateReq.DeviceName);
            if (!success)
            {
                return new NotFoundResult();
            }

            _logger.LogInformation("Updated Automate settings for user {UserId}", userId);
            return new OkResult();
        }
    }
}
