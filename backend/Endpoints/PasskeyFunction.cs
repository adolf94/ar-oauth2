using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using backend.Services;
using backend.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Passwordless;

namespace backend.Endpoints
{
    public class PasskeyLoginRequest
    {
        public string Token { get; set; } = string.Empty;
        public string? ClientId { get; set; }
        public string? RedirectUri { get; set; }
        public string? State { get; set; }
        public string? CodeChallenge { get; set; }
        public string? CodeChallengeMethod { get; set; }
        public string? Scope { get; set; }
    }

    public class PasskeyFunction
    {
        private readonly ILogger<PasskeyFunction> _logger;
        private readonly IPasswordlessClient _passwordlessClient;
        private readonly UserService _userService;
        private readonly AuthCodeService _authCodeService;
        private readonly TokenService _tokenService;

        public PasskeyFunction(
            ILogger<PasskeyFunction> logger,
            IPasswordlessClient passwordlessClient,
            UserService userService,
            AuthCodeService authCodeService,
            TokenService tokenService)
        {
            _logger = logger;
            _passwordlessClient = passwordlessClient;
            _userService = userService;
            _authCodeService = authCodeService;
            _tokenService = tokenService;
        }

        [Function("PasskeyLogin")]
        public async Task<IActionResult> Login(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "passkey/login")] HttpRequest req)
        {
            _logger.LogInformation("Passkey login initiated.");

            var requestBody = await req.ReadFromJsonAsync<PasskeyLoginRequest>();
            if (requestBody == null || string.IsNullOrEmpty(requestBody.Token))
            {
                return new BadRequestObjectResult(new { error = "invalid_request", error_description = "Token is required." });
            }

            try
            {
                // 1. Verify the passkey token
                var verifiedUser = await _passwordlessClient.VerifyAuthenticationTokenAsync(requestBody.Token);
                
                // 2. Resolve the user from the database using the Passwordless UserId (mapped to AR Auth User Id)
                var user = await _userService.GetByIdAsync(verifiedUser.UserId);
                if (user == null)
                {
                    _logger.LogWarning("Passkey verified for User ID {UserId}, but user not found in database.", verifiedUser.UserId);
                    return new UnauthorizedObjectResult(new { error = "user_not_found" });
                }

                // 3. Generate AR Auth code (Authorization Code Flow with PKCE)
                var authCode = await _authCodeService.CreateAuthCodeAsync(
                    requestBody.ClientId ?? string.Empty,
                    user.Id,
                    requestBody.RedirectUri ?? string.Empty,
                    requestBody.CodeChallenge ?? string.Empty,
                    requestBody.CodeChallengeMethod ?? string.Empty,
                    requestBody.Scope ?? string.Empty
                );

                return new OkObjectResult(new { code = authCode.Id, state = requestBody.State });
            }
            catch (PasswordlessApiException ex)
            {
                _logger.LogError(ex, "Passwordless verification failed: {Details}", ex.Details);
                return new UnauthorizedObjectResult(new { error = "passkey_verification_failed", details = ex.Details });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during Passkey login.");
                return new StatusCodeResult(500);
            }
        }

        [Function("PasskeyRegisterStart")]
        public async Task<IActionResult> RegisterStart(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "passkey/register/start")] HttpRequest req)
        {
            // Try to get email from authenticated user first
            var (principal, authError) = AuthHelper.ValidateToken(req, _tokenService, _logger);
            string? email = principal?.FindFirst(ClaimTypes.Email)?.Value;

            if (string.IsNullOrEmpty(email))
            {
                // Fallback to body for initial enrollment testing if not authenticated
                var body = await req.ReadFromJsonAsync<Dictionary<string, string>>();
                if (body == null || !body.ContainsKey("email"))
                {
                    return new BadRequestObjectResult(new { error = "email_required" });
                }
                email = body["email"];
            }

            var user = await _userService.GetByEmailAsync(email);
            if (user == null)
            {
                 user = await _userService.CreateUserAsync(email, new List<string> { "user" });
            }

            var registerOptions = new RegisterOptions(user.Id, email)
            {
                Username = email,
                DisplayName = email,
                Aliases = new HashSet<string> { email }
            };

            try
            {
                var token = await _passwordlessClient.CreateRegisterTokenAsync(registerOptions);
                return new OkObjectResult(token);
            }
            catch (PasswordlessApiException ex)
            {
                _logger.LogError(ex, "Failed to create registration token: {Details}", ex.Details);
                return new BadRequestObjectResult(new { error = "registration_failed", details = ex.Details });
            }
        }

        [Function("ListPasskeys")]
        public async Task<IActionResult> ListPasskeys(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "passkey/list")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateToken(req, _tokenService, _logger);
            if (error != null) return error;

            var userId = principal!.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId)) return new UnauthorizedResult();

            try
            {
                var credentials = await _passwordlessClient.ListCredentialsAsync(userId);
                return new OkObjectResult(credentials);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error listing passkeys for user {UserId}", userId);
                return new StatusCodeResult(500);
            }
        }

        [Function("DeletePasskey")]
        public async Task<IActionResult> DeletePasskey(
            [HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "passkey/{credentialId}")] HttpRequest req, string credentialId)
        {
            var (principal, error) = AuthHelper.ValidateToken(req, _tokenService, _logger);
            if (error != null) return error;

            try
            {
                await _passwordlessClient.DeleteCredentialAsync(credentialId);
                return new OkResult();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting passkey {CredentialId}", credentialId);
                return new StatusCodeResult(500);
            }
        }
    }
}
