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
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "api/login/google")] HttpRequest req)
        {
            _logger.LogInformation("Google OAuth login initiated.");

            // Capture the SP's authorization parameters
            var clientId = (string?)req.Query["client_id"] ?? string.Empty;
            var redirectUri = (string?)req.Query["redirect_uri"] ?? string.Empty;
            var stateStr = (string?)req.Query["state"] ?? string.Empty;
            var codeChallenge = (string?)req.Query["code_challenge"] ?? string.Empty;
            var codeChallengeMethod = (string?)req.Query["code_challenge_method"] ?? string.Empty;
            var scope = (string?)req.Query["scope"] ?? string.Empty;
            var linkToken = (string?)req.Query["link_token"];

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

            if (!string.IsNullOrEmpty(linkToken))
            {
                claims.Add(new Claim("link_token", linkToken));
            }

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
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "api/login/google/callback")] HttpRequest req)
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
            var linkToken = principal.FindFirst("link_token")?.Value;

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

            var googleEmail = payload.Email;
            var googleSub = payload.Subject;
            var googleName = payload.Name;
            // 4. Map Google User
            var user = await _userService.GetByExternalIdentityAsync("google", googleSub);
            
            // Link Mode: If we have a link token, we MUST link to that user
            if (!string.IsNullOrEmpty(linkToken))
            {
                try {
                    var linkTokenHandler = new JwtSecurityTokenHandler();
                    var linkPrincipal = linkTokenHandler.ValidateToken(linkToken, new TokenValidationParameters {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKeys = _rsaKeyService.GetValidationKeys(),
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ValidateLifetime = true
                    }, out _);
                    var targetUserId = linkPrincipal.FindFirst("link_user_id")?.Value;
                    if (!string.IsNullOrEmpty(targetUserId)) {
                        _logger.LogInformation("Linking Google {Sub} to user {TargetUserId} via link_token", googleSub, targetUserId);
                        await _userService.LinkExternalIdentityAsync(targetUserId, "google", googleSub, googleSub, googleName, googleEmail);
                        user = await _userService.GetByIdAsync(targetUserId);
                    }
                } catch (Exception ex) {
                    _logger.LogWarning(ex, "Invalid link_token in Google callback.");
                }
            }

            if (user == null)
            {
                // Fallback: Check by the real Google email
                if (!string.IsNullOrEmpty(googleEmail))
                {
                    user = await _userService.GetByEmailAsync(googleEmail);
                }

                if (user == null)
                {
                    _logger.LogInformation("User {Sub} not found — creating new user.", googleSub);
                    user = await _userService.CreateUserAsync(googleEmail ?? string.Empty, null, new List<string> { "unregistered" }, "google", googleSub, googleName, googleSub, googleEmail);
                }
                else
                {
                    // If user found by email, link to Google ID
                    _logger.LogInformation("Found existing user by email {Email} — linking to Google ID {Sub}", googleEmail, googleSub);
                    await _userService.LinkExternalIdentityAsync(user.Id, "google", googleSub, googleSub, googleName, googleEmail);
                }
            }

            // Always update identity details
            await _userService.UpdateExternalIdentityDetailsAsync(user.Id, "google", googleSub, googleSub, googleName, googleEmail);

            // Always use the name from Google
            if (!string.IsNullOrEmpty(googleName) && (user.Name != googleName))
            {
                _logger.LogInformation("Updating name for user {UserId} from Google: {OldName} -> {NewName}", user.Id, user.Name, googleName);
                await _userService.UpdateUserAsync(user.Id, user.MobileNumber, user.Roles, googleName);
                user.Name = googleName;
            }

            // 4. Generate Atlas Rig code
            var authCode = await _authCodeService.CreateAuthCodeAsync(
                spClientId,
                user.Id,
                spRedirectUri,
                spCodeChallenge,
                spCodeChallengeMethod,
                spScope
            );

            // 5. Update Recently Used Accounts cookie
            var recentIds = AuthHelper.GetRecentUserIds(req);
            recentIds.Insert(0, user.Id);
            AuthHelper.SetRecentUserIds(req.HttpContext.Response, recentIds);

            // 5. Redirect back to Atlas Rig Frontend success page first
            var atlasRigHost = _appConfig.Jwt.Issuer.Replace("/api", ""); 
            var finalRedirectUrl = $"{atlasRigHost}/login/success" +
                                   $"?code={Uri.EscapeDataString(authCode.Id)}" +
                                   $"&state={Uri.EscapeDataString(spOriginalState ?? "")}" +
                                   $"&redirect_uri={Uri.EscapeDataString(spRedirectUri)}" +
                                   $"&email={Uri.EscapeDataString(user.Email)}" +
                                   $"&id={Uri.EscapeDataString(user.Id)}" +
                                   $"&provider=google";
            
            return new RedirectResult(finalRedirectUrl);
        }
    }
}
