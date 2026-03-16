using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using backend.Services;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace backend.Endpoints
{
    public class GoogleTokenResponse
    {
        [JsonPropertyName("id_token")]
        public string IdToken { get; set; } = string.Empty;
    }

    public class GoogleOAuthFunction
    {
        private readonly ILogger<GoogleOAuthFunction> _logger;
        private readonly AuthCodeService _authCodeService;
        private readonly UserService _userService;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly Configuration.AppConfig _appConfig;
        private readonly RsaKeyService _rsaKeyService;

        public GoogleOAuthFunction(
            ILogger<GoogleOAuthFunction> logger,
            AuthCodeService authCodeService,
            UserService userService,
            IHttpClientFactory httpClientFactory,
            Configuration.AppConfig appConfig,
            RsaKeyService rsaKeyService)
        {
            _logger = logger;
            _authCodeService = authCodeService;
            _userService = userService;
            _httpClientFactory = httpClientFactory;
            _appConfig = appConfig;
            _rsaKeyService = rsaKeyService;
        }

        [Function("GoogleOAuthLogin")]
        public IActionResult Login(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "login/google")] HttpRequest req)
        {
            _logger.LogInformation("Google OAuth login initiated.");

            // Capture the SP's authorization parameters
            var clientId = (string?)req.Query["client_id"] ?? string.Empty;
            var redirectUri = (string?)req.Query["redirect_uri"] ?? string.Empty;
            var stateStr = (string?)req.Query["state"] ?? string.Empty;
            var codeChallenge = (string?)req.Query["code_challenge"] ?? string.Empty;
            var codeChallengeMethod = (string?)req.Query["code_challenge_method"] ?? string.Empty;
            var scope = (string?)req.Query["scope"] ?? string.Empty;

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri))
            {
                return new BadRequestObjectResult(new { error = "invalid_request", error_description = "client_id and redirect_uri are required." });
            }

            // Securely package these parameters into a signed JWT as the Google 'state'
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = _rsaKeyService.GetSigningKey();

            var claims = new List<Claim>
            {
                new Claim("client_id", clientId),
                new Claim("redirect_uri", redirectUri),
                new Claim("original_state", stateStr),
                new Claim("code_challenge", codeChallenge),
                new Claim("code_challenge_method", codeChallengeMethod),
                new Claim("scope", scope)
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(15), // state is valid for 15 mins
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
            };

            var relayState = tokenHandler.WriteToken(tokenHandler.CreateToken(tokenDescriptor));

            var googleClientId = _appConfig.Google.ClientId;
            if (string.IsNullOrEmpty(googleClientId))
            {
                _logger.LogError("Google.ClientId is not set.");
                return new StatusCodeResult(500);
            }

            // The URL our own backend is listening on for Google to redirect back to
            var googleCallbackUrl = _appConfig.Google.RedirectUri;
            if (string.IsNullOrEmpty(googleCallbackUrl))
            {
                var issuer = _appConfig.Jwt.Issuer;
                googleCallbackUrl = $"{issuer}/login/google/callback";
            }

            // Redirect the user to Google
            var authUrl = $"https://accounts.google.com/o/oauth2/v2/auth" +
                          $"?client_id={Uri.EscapeDataString(googleClientId)}" +
                          $"&redirect_uri={Uri.EscapeDataString(googleCallbackUrl)}" +
                          $"&response_type=code" +
                          $"&scope=openid%20email%20profile" +
                          $"&state={Uri.EscapeDataString(relayState)}" +
                          $"&prompt=select_account";

            return new RedirectResult(authUrl);
        }

        [Function("GoogleOAuthCallback")]
        public async Task<IActionResult> Callback(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "login/google/callback")] HttpRequest req)
        {
            _logger.LogInformation("Google OAuth callback invoked.");

            var code = (string?)req.Query["code"];
            var state = (string?)req.Query["state"];
            var error = (string?)req.Query["error"];

            if (!string.IsNullOrEmpty(error))
                return new BadRequestObjectResult(new { error = "google_auth_failed", error_description = error });

            if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
                return new BadRequestObjectResult(new { error = "invalid_request", error_description = "code and state are required." });

            // 1. Validate the relay state (JWT) and extract original SP parameters
            ClaimsPrincipal principal;
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var keys = _rsaKeyService.GetValidationKeys();

                principal = tokenHandler.ValidateToken(state, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = keys,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                }, out _);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to validate Google relay state.");
                return new BadRequestObjectResult(new { error = "invalid_state", error_description = "State token is invalid or expired." });
            }

            var spClientId = principal.FindFirst("client_id")?.Value ?? "";
            var spRedirectUri = principal.FindFirst("redirect_uri")?.Value ?? "";
            var spOriginalState = principal.FindFirst("original_state")?.Value ?? "";
            var spCodeChallenge = principal.FindFirst("code_challenge")?.Value ?? "";
            var spCodeChallengeMethod = principal.FindFirst("code_challenge_method")?.Value ?? "";
            var spScope = principal.FindFirst("scope")?.Value ?? "";

            // 2. Exchange the Google code for an ID token
            var googleClientId = _appConfig.Google.ClientId;
            var googleClientSecret = _appConfig.Google.ClientSecret;
            var googleCallbackUrl = _appConfig.Google.RedirectUri;

            if (string.IsNullOrEmpty(googleCallbackUrl))
            {
                var issuer = _appConfig.Jwt.Issuer;
                googleCallbackUrl = $"{issuer}/login/google/callback";
            }

            if (string.IsNullOrEmpty(googleClientId) || string.IsNullOrEmpty(googleClientSecret))
            {
                _logger.LogError("Google credentials are not fully configured.");
                return new StatusCodeResult(500);
            }

            var client = _httpClientFactory.CreateClient();
            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = googleClientId,
                ["client_secret"] = googleClientSecret,
                ["code"] = code,
                ["grant_type"] = "authorization_code",
                ["redirect_uri"] = googleCallbackUrl
            });

            var tokenResponse = await client.PostAsync("https://oauth2.googleapis.com/token", tokenRequest);
            if (!tokenResponse.IsSuccessStatusCode)
            {
                var body = await tokenResponse.Content.ReadAsStringAsync();
                _logger.LogError("Failed to exchange code with Google: {Body}", body);
                return new BadRequestObjectResult(new { error = "google_exchange_failed" });
            }

            var tokenData = await tokenResponse.Content.ReadFromJsonAsync<GoogleTokenResponse>();
            if (tokenData == null || string.IsNullOrEmpty(tokenData.IdToken))
            {
                return new BadRequestObjectResult(new { error = "google_exchange_empty" });
            }

            // 3. Validate Google ID token and extract user
            GoogleJsonWebSignature.Payload payload;
            try
            {
                payload = await GoogleJsonWebSignature.ValidateAsync(tokenData.IdToken, new GoogleJsonWebSignature.ValidationSettings
                {
                    Audience = new[] { googleClientId }
                });
            }
            catch (InvalidJwtException ex)
            {
                _logger.LogWarning(ex, "Invalid Google ID token.");
                return new UnauthorizedObjectResult(new { error = "invalid_token", error_description = "Invalid Google ID token." });
            }

            var email = payload.Email;
            var user = await _userService.GetByEmailAsync(email);
            if (user == null)
            {
                _logger.LogInformation("User {Email} not found — creating stub user for Google login.", email);
                user = await _userService.CreateUserAsync(email, null, new List<string> { "unregistered" });
            }

            // 4. Generate AR Auth code
            var authCode = await _authCodeService.CreateAuthCodeAsync(
                spClientId,
                user.Id,
                spRedirectUri,
                spCodeChallenge,
                spCodeChallengeMethod,
                spScope
            );

            // 5. Redirect back to original SP redirect_uri with the AR Auth code
            var finalRedirectUrl = $"{spRedirectUri}?code={Uri.EscapeDataString(authCode.Id)}";
            if (!string.IsNullOrEmpty(spOriginalState))
            {
                finalRedirectUrl += $"&state={Uri.EscapeDataString(spOriginalState)}";
            }

            return new RedirectResult(finalRedirectUrl);
        }
    }
}
