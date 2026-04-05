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
        private readonly IAuthCodeService _authCodeService;
        private readonly IUserService _userService;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly Configuration.AppConfig _appConfig;
        private readonly IRsaKeyService _rsaKeyService;
        private readonly ITokenService _tokenService;
        private readonly IDbHelper _dbHelper;

        public GoogleOAuthFunction(
            ILogger<GoogleOAuthFunction> logger,
            IAuthCodeService authCodeService,
            IUserService userService,
            IHttpClientFactory httpClientFactory,
            Configuration.AppConfig appConfig,
            IRsaKeyService rsaKeyService,
            ITokenService tokenService,
            IDbHelper dbHelper)
        {
            _logger = logger;
            _authCodeService = authCodeService;
            _userService = userService;
            _httpClientFactory = httpClientFactory;
            _appConfig = appConfig;
            _rsaKeyService = rsaKeyService;
            _tokenService = tokenService;
            _dbHelper = dbHelper;
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
            var googlePicture = payload.Picture;
            // 4. Map Google User
            var user = await _userService.GetByExternalIdentityAsync("google", googleSub);
            
            _dbHelper.BeginBatch();

            string? linkedTelegramId = null;
            // Link Mode: If we have a link token, we MUST link to that (or provided) user
            if (!string.IsNullOrEmpty(linkToken))
            {
                try {
                    // 1. Try to validate as a new signed Link Token (with telegram_id)
                    var linkPrincipal = _tokenService.ValidateLinkToken(linkToken);
                    if (linkPrincipal != null) {
                        linkedTelegramId = linkPrincipal.FindFirst("telegram_id")?.Value;
                        if (!string.IsNullOrEmpty(linkedTelegramId)) {
                             _logger.LogInformation("Recognized Telegram {Id} to link via Google flow.", linkedTelegramId);
                        }
                    } else {
                        // 2. Fallback to old link_user_id logic (legacy)
                        var tokenHandler = new JwtSecurityTokenHandler();
                        var oldPrincipal = tokenHandler.ValidateToken(linkToken, new TokenValidationParameters {
                            ValidateIssuerSigningKey = true,
                            IssuerSigningKeys = _rsaKeyService.GetValidationKeys(),
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = true
                        }, out _);
                        var targetUserId = oldPrincipal.FindFirst("link_user_id")?.Value;
                        if (!string.IsNullOrEmpty(targetUserId)) {
                            _logger.LogInformation("Linking current Google identity to user {TargetUserId} via legacy link_token", targetUserId);
                            var targetUser = await _userService.GetByIdAsync(targetUserId);
                            if (targetUser != null) {
                                user = targetUser;
                            }
                        }
                    }
                } catch (Exception ex) {
                    _logger.LogWarning(ex, "Failed to process link_token in Google callback.");
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
                    user = await _userService.CreateUserAsync(googleEmail ?? string.Empty, null, new List<string> { "unregistered" }, "google", googleSub, googleName, googleSub, googleEmail, null, googlePicture);
                }
                else
                {
                    // If user found by email, link to Google ID
                    _logger.LogInformation("Found existing user by email {Email} — linking to Google ID {Sub}", googleEmail, googleSub);
                    user.SyncIdentity("google", googleSub, googleSub, googleName, googleEmail, null, googlePicture);
                }
            }

            // Always update identity details and sync top-level fields
            user.SyncIdentity("google", googleSub, googleSub, googleName, googleEmail, null, googlePicture);

            // Link the specific Telegram ID from link_token if present
            if (!string.IsNullOrEmpty(linkedTelegramId))
            {
                 await _userService.LinkTelegramIdentityAsync(user, linkedTelegramId);
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

            await _dbHelper.CommitBatchAsync();

            // 6. Set active session cookie (HttpOnly/Secure)
            var sessionToken = _tokenService.GenerateSessionToken(user);
            AuthHelper.SetSessionCookie(req.HttpContext.Response, sessionToken);

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
