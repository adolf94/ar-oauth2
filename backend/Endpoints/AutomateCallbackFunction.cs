using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using backend.Services;
using backend.Data;
using Microsoft.EntityFrameworkCore;

namespace backend.Endpoints
{
    public class AutomatePushRequest
    {
        public string? Code { get; set; }
        public string? State { get; set; }
    }

    public class AutomateCallbackFunction
    {
        private readonly ILogger<AutomateCallbackFunction> _logger;
        private readonly AppDbContext _dbContext;
        private readonly UserService _userService;
        private readonly LlamalabsService _llamalabsService;

        public AutomateCallbackFunction(
            ILogger<AutomateCallbackFunction> logger,
            AppDbContext dbContext,
            UserService userService,
            LlamalabsService llamalabsService)
        {
            _logger = logger;
            _dbContext = dbContext;
            _userService = userService;
            _llamalabsService = llamalabsService;
        }

        [Function("AutomatePush")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "api/automate/push")] HttpRequest req)
        {
            _logger.LogInformation("Automate push API invoked.");

            var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            var pushReq = JsonSerializer.Deserialize<AutomatePushRequest>(requestBody, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (pushReq == null || string.IsNullOrEmpty(pushReq.Code))
            {
                return new BadRequestObjectResult(new { error = "invalid_request", error_description = "code is required." });
            }

            // 1. Verify that the auth code exists and is valid
            // We do NOT consume (remove) it here, because the phone (Automate) will use it 
            // to call the standard /api/token endpoint with its PKCE code_verifier.
            var authCode = await _dbContext.AuthCodes.FirstOrDefaultAsync(c => c.Id == pushReq.Code);

            if (authCode == null || authCode.ExpiresAt < DateTime.UtcNow)
            {
                _logger.LogWarning("Invalid or expired auth code provided to automate push API: {Code}", pushReq.Code);
                return new UnauthorizedObjectResult(new { error = "invalid_grant", error_description = "Code is invalid or expired." });
            }

            var user = await _userService.GetByIdAsync(authCode.UserId);
            if (user == null)
            {
                 return new UnauthorizedObjectResult(new { error = "invalid_grant", error_description = "User not found." });
            }

            // 2. Push the CODE and STATE to Llamalabs Automate Cloud Receive
            if (!string.IsNullOrEmpty(user.AutomateSecret) && !string.IsNullOrEmpty(user.AutomateDeviceName))
            {
                _logger.LogInformation("Pushing auth code to device {Device} for user {Email}", user.AutomateDeviceName, user.Email);
                
                var pushPayload = new
                {
                    action = "atlas_auth_code",
                    code = pushReq.Code,
                    state = pushReq.State
                };

                var pushed = await _llamalabsService.SendCloudReceiveAsync(user.Email, user.AutomateSecret, user.AutomateDeviceName, pushPayload);
                if (!pushed)
                {
                    return new ObjectResult(new { error = "delivery_failed", error_description = "The authorization code was generated but could not be delivered to the device via LlamaLab Automate. Please check your Automate settings and internet connection." }) { StatusCode = 502 };
                }
            }
            else
            {
                _logger.LogWarning("User {Email} has no Automate configuration. No push sent.", user.Email);
                return new BadRequestObjectResult(new { error = "config_missing", error_description = "Automate configuration missing for the user." });
            }

            return new OkObjectResult(new { success = true });
        }
    }
}
