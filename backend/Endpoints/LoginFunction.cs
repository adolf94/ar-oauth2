using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using backend.Services;
using System.Text.Json;
using System.IO;
using Google.Apis.Auth;

namespace backend.Endpoints
{
    public class LoginRequest
    {
        public string google_id_token { get; set; } = string.Empty;
        
        // For testing only: email lookup with no password.
        public string client_id { get; set; } = string.Empty;
        public string redirect_uri { get; set; } = string.Empty;
        public string code_challenge { get; set; } = string.Empty;
        public string code_challenge_method { get; set; } = string.Empty;
        public string scope { get; set; } = string.Empty;
        public string state { get; set; } = string.Empty;
    }

    public class LoginFunction
    {
        private readonly ILogger<LoginFunction> _logger;
        private readonly AuthCodeService _authCodeService;
        private readonly UserService _userService;

        public LoginFunction(ILogger<LoginFunction> logger, AuthCodeService authCodeService, UserService userService)
        {
            _logger = logger;
            _authCodeService = authCodeService;
            _userService = userService;
        }

        [Function("Login")]
        public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "api/login")] HttpRequest req)
        {
            _logger.LogInformation("Login endpoint invoked.");

            var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            var loginReq = JsonSerializer.Deserialize<LoginRequest>(requestBody, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (loginReq == null)
                return new BadRequestObjectResult(new { error = "invalid_request", error_description = "Invalid payload." });

            string targetEmail = string.Empty;

            // 1. Google Login Flow
            if (!string.IsNullOrEmpty(loginReq.google_id_token))
            {
                try
                {
                    var googleClientId = Environment.GetEnvironmentVariable("GoogleClientId");
                    if (string.IsNullOrEmpty(googleClientId))
                    {
                        _logger.LogError("GoogleClientId is not set in environment.");
                        return new StatusCodeResult(500);
                    }

                    var payload = await GoogleJsonWebSignature.ValidateAsync(loginReq.google_id_token, new GoogleJsonWebSignature.ValidationSettings
                    {
                        Audience = new[] { googleClientId }
                    });

                    targetEmail = payload.Email;
                    var googleName = payload.Name;
                    _logger.LogInformation("Successfully validated Google ID token for {Email}", targetEmail);

                    var user = await _userService.GetByEmailAsync(targetEmail);
                    if (user == null)
                    {
                        _logger.LogInformation("User {Email} not found — creating user from Google provisioning.", targetEmail);
                        user = await _userService.CreateUserAsync(targetEmail, null, new System.Collections.Generic.List<string> { "user" }, "google", payload.Subject, googleName);
                    }
                    
                    // Always use the name from Google
                    if (!string.IsNullOrEmpty(googleName) && user.Name != googleName)
                    {
                        await _userService.UpdateUserAsync(user.Id, user.MobileNumber, user.Roles, googleName);
                        user.Name = googleName;
                    }

                    // Generate authorization code
                    var authCode = await _authCodeService.CreateAuthCodeAsync(
                        loginReq.client_id,
                        user.Id,
                        loginReq.redirect_uri,
                        loginReq.code_challenge,
                        loginReq.code_challenge_method,
                        loginReq.scope
                    );

                    // Return code + state so the SPA can redirect to the redirect_uri
                    return new OkObjectResult(new { code = authCode.Id, state = loginReq.state });
                }
                catch (InvalidJwtException ex)
                {
                    _logger.LogWarning(ex, "Invalid Google ID token.");
                    return new UnauthorizedObjectResult(new { error = "invalid_token", error_description = "Invalid Google ID token." });
                }
            }
            else
            {
                return new BadRequestObjectResult(new { error = "invalid_request", error_description = "google_id_token is required." });
            }
        }
    }
}
