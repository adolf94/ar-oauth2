using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using backend.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace backend.Endpoints
{
    public class TelegramOAuthFunction
    {
        private readonly ILogger<TelegramOAuthFunction> _logger;
        private readonly AuthCodeService _authCodeService;
        private readonly UserService _userService;
        private readonly Configuration.AppConfig _appConfig;
        private readonly RsaKeyService _rsaKeyService;
        private readonly IHttpClientFactory _httpClientFactory;

        private const string RelayStateCookieName = "tg_relay_state";

        public TelegramOAuthFunction(
            ILogger<TelegramOAuthFunction> logger,
            AuthCodeService authCodeService,
            UserService userService,
            Configuration.AppConfig appConfig,
            RsaKeyService rsaKeyService,
            IHttpClientFactory httpClientFactory)
        {
            _logger = logger;
            _authCodeService = authCodeService;
            _userService = userService;
            _appConfig = appConfig;
            _rsaKeyService = rsaKeyService;
            _httpClientFactory = httpClientFactory;
        }

        [Function("AuthTelegramLogin")]
        public async Task<IActionResult> Login(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "api/login/telegram")] HttpRequest req)
        {
            _logger.LogInformation("[DEBUG] api/login/telegram invoked with query: {Query}", req.QueryString);
            await Task.Yield(); // Keep it async for consistency
            _logger.LogInformation("Telegram OAuth login initiated.");

            // Capture the SP's authorization parameters
            var clientId = (string?)req.Query["client_id"] ?? string.Empty;
            var redirectUri = (string?)req.Query["redirect_uri"] ?? string.Empty;
            var stateStr = (string?)req.Query["state"] ?? string.Empty;
            var codeChallenge = (string?)req.Query["code_challenge"] ?? string.Empty;
            var codeChallengeMethod = (string?)req.Query["code_challenge_method"] ?? string.Empty;
            var spScope = (string?)req.Query["scope"] ?? string.Empty;
            var linkToken = (string?)req.Query["link_token"];

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri))
            {
                return new BadRequestObjectResult(new { error = "invalid_request", error_description = "client_id and redirect_uri are required." });
            }

            // Securely package these parameters into a signed JWT as the 'relay state'
            // Since Telegram doesn't support a generic state param in the widget login, we store it in a cookie.
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = _rsaKeyService.GetSigningKey();

            var claims = new List<Claim>
            {
                new Claim("client_id", clientId),
                new Claim("redirect_uri", redirectUri),
                new Claim("original_state", stateStr),
                new Claim("code_challenge", codeChallenge),
                new Claim("code_challenge_method", codeChallengeMethod),
                new Claim("scope", spScope)
            };

            if (!string.IsNullOrEmpty(linkToken))
            {
                claims.Add(new Claim("link_token", linkToken));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(15), 
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
            };

            var relayState = tokenHandler.WriteToken(tokenHandler.CreateToken(tokenDescriptor));

            // Set HttpOnly cookie for the relay state
            req.HttpContext.Response.Cookies.Append(RelayStateCookieName, relayState, new CookieOptions
            {
                HttpOnly = true,
                Secure = true, // Ensure SSL
                SameSite = SameSiteMode.None, // Support cross-site redirect
                Expires = DateTimeOffset.UtcNow.AddMinutes(15)
            });

            var botId = _appConfig.Telegram.ClientId; 
            if (string.IsNullOrEmpty(botId) && !string.IsNullOrEmpty(_appConfig.Telegram.ClientSecret))
            {
                // Extract bot ID from token (it's the numeric part before the first colon)
                var colonIndex = _appConfig.Telegram.ClientSecret.IndexOf(':');
                if (colonIndex > 0)
                {
                    botId = _appConfig.Telegram.ClientSecret.Substring(0, colonIndex);
                }
            }
            
            var callbackUrl = _appConfig.Telegram.RedirectUri;
            if (string.IsNullOrEmpty(callbackUrl))
            {
                callbackUrl = $"{_appConfig.Jwt.Issuer}/login/telegram/callback";
            }

            // Redirect to Telegram's standard OIDC Authorization endpoint
            var authUrl = $"https://oauth.telegram.org/auth" +
                          $"?client_id={Uri.EscapeDataString(botId ?? "")}" +
                          $"&redirect_uri={Uri.EscapeDataString(callbackUrl)}" +
                          $"&response_type=code" +
                          $"&scope=openid%20profile%20phone%20telegram:bot_access" +
                          $"&state={Uri.EscapeDataString(relayState)}";

            return new RedirectResult(authUrl);
        }

        [Function("AuthTelegramCallback")]
        public async Task<IActionResult> Callback(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "api/login/telegram/callback")] HttpRequest req)
        {
            _logger.LogInformation("[DEBUG] api/login/telegram/callback invoked.");
            _logger.LogInformation("Telegram OAuth callback invoked.");

            // 1. Recover original OIDC parameters from cookie
            if (!req.Cookies.TryGetValue(RelayStateCookieName, out var relayState) || string.IsNullOrEmpty(relayState))
            {
                 _logger.LogWarning("Missing or expired Telegram relay state cookie.");
                 return new BadRequestObjectResult(new { error = "invalid_state", error_description = "Session expired or invalid state." });
            }

            ClaimsPrincipal statePrincipal;
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var keys = _rsaKeyService.GetValidationKeys();

                statePrincipal = tokenHandler.ValidateToken(relayState, new TokenValidationParameters
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
                _logger.LogWarning(ex, "Failed to validate Telegram relay state JWT.");
                return new BadRequestObjectResult(new { error = "invalid_state" });
            }

            var spClientId = statePrincipal.FindFirst("client_id")?.Value ?? "";
            var spRedirectUri = statePrincipal.FindFirst("redirect_uri")?.Value ?? "";
            var spOriginalState = statePrincipal.FindFirst("original_state")?.Value ?? "";
            var spCodeChallenge = statePrincipal.FindFirst("code_challenge")?.Value ?? "";
            var spCodeChallengeMethod = statePrincipal.FindFirst("code_challenge_method")?.Value ?? "";
            var spScope = statePrincipal.FindFirst("scope")?.Value ?? "";
            var linkToken = statePrincipal.FindFirst("link_token")?.Value;

            // 2. Standard OIDC Code Exchange
            var code = (string?)req.Query["code"];
            if (string.IsNullOrEmpty(code))
            {
                _logger.LogWarning("Missing code from Telegram callback.");
                return new BadRequestObjectResult(new { error = "missing_code" });
            }

            var botId = _appConfig.Telegram.ClientId; 
            var botToken = _appConfig.Telegram.ClientSecret;

            var callbackUrl = _appConfig.Telegram.RedirectUri;
            if (string.IsNullOrEmpty(callbackUrl))
            {
                callbackUrl = $"{_appConfig.Jwt.Issuer}/login/telegram/callback";
            }

            var httpClient = _httpClientFactory.CreateClient();
            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = callbackUrl,
                ["client_id"] = botId,
                ["client_secret"] = botToken
            });

            var tokenResponse = await httpClient.PostAsync("https://oauth.telegram.org/token", tokenRequest);
            if (!tokenResponse.IsSuccessStatusCode)
            {
                var errorBody = await tokenResponse.Content.ReadAsStringAsync();
                _logger.LogError("Telegram token exchange failed: {ErrorBody}", errorBody);
                return new BadRequestObjectResult(new { error = "token_exchange_failed" });
            }

            var tokenData = await tokenResponse.Content.ReadFromJsonAsync<TelegramTokenResponse>();
            if (tokenData == null || string.IsNullOrEmpty(tokenData.IdToken))
            {
                return new BadRequestObjectResult(new { error = "empty_token" });
            }

            // 3. Extract Claims from ID Token
            var handler = new JwtSecurityTokenHandler();
            var idTokenJson = handler.ReadJwtToken(tokenData.IdToken);
            var telegramId = idTokenJson.Subject; // 'sub' claim
            var telegramPhone = idTokenJson.Claims.FirstOrDefault(c => c.Type == "phone_number")?.Value;
            var telegramFirstName = idTokenJson.Claims.FirstOrDefault(c => c.Type == "given_name")?.Value;
            var telegramLastName = idTokenJson.Claims.FirstOrDefault(c => c.Type == "family_name")?.Value;
            var telegramName = idTokenJson.Claims.FirstOrDefault(c => c.Type == "name")?.Value 
                  ?? (string.IsNullOrEmpty(telegramLastName) ? telegramFirstName : $"{telegramFirstName} {telegramLastName}");

            // 4. Map Telegram User
            var idBasedEmail = $"{telegramId}@telegram.org";
            var user = await _userService.GetByExternalIdentityAsync("telegram", telegramId);
            
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
                        _logger.LogInformation("Linking Telegram {Id} to user {TargetUserId} via link_token", telegramId, targetUserId);
                        await _userService.LinkExternalIdentityAsync(targetUserId, "telegram", telegramId);
                        user = await _userService.GetByIdAsync(targetUserId);
                    }
                } catch (Exception ex) {
                    _logger.LogWarning(ex, "Invalid link_token in Telegram callback.");
                }
            }
            if (user == null)
            {
                user = await _userService.GetByEmailAsync(idBasedEmail);
                if (user == null)
                {
                    _logger.LogInformation("Creating new Telegram user {Id}", telegramId);
                    user = await _userService.CreateUserAsync(idBasedEmail, telegramPhone, new List<string> { "unregistered" }, "telegram", telegramId, telegramName);
                }
            }

            // Only set the name from Telegram if there is no Name saved yet
            if (string.IsNullOrEmpty(user.Name) && !string.IsNullOrEmpty(telegramName))
            {
                _logger.LogInformation("Setting name for user {UserId} from Telegram: {NewName}", user.Id, telegramName);
                await _userService.UpdateUserAsync(user.Id, telegramPhone ?? user.MobileNumber, user.Roles, telegramName);
                user.Name = telegramName;
                user.MobileNumber = telegramPhone ?? user.MobileNumber;
            }
            else if (!string.IsNullOrEmpty(telegramPhone) && string.IsNullOrEmpty(user.MobileNumber))
            {
                await _userService.UpdateUserAsync(user.Id, telegramPhone, user.Roles);
                user.MobileNumber = telegramPhone;
            }

            // 5. Generate Atlas Rig code
            var authCode = await _authCodeService.CreateAuthCodeAsync(
                spClientId,
                user.Id,
                spRedirectUri,
                spCodeChallenge,
                spCodeChallengeMethod,
                spScope
            );

            // 6. Update Recently Used Accounts cookie
            var recentIds = AuthHelper.GetRecentUserIds(req);
            recentIds.Insert(0, user.Id);
            AuthHelper.SetRecentUserIds(req.HttpContext.Response, recentIds);

            // Cleanup cookie
            req.HttpContext.Response.Cookies.Delete(RelayStateCookieName);

            // 7. Redirect back to Atlas Rig Frontend
            var atlasRigHost = _appConfig.Jwt.Issuer.Replace("/api", ""); 
            var finalRedirectUrl = $"{atlasRigHost}/login/success" +
                                   $"?code={Uri.EscapeDataString(authCode.Id)}" +
                                   $"&state={Uri.EscapeDataString(spOriginalState ?? "")}" +
                                   $"&redirect_uri={Uri.EscapeDataString(spRedirectUri)}" +
                                   $"&email={Uri.EscapeDataString(user.Email)}" +
                                   $"&id={Uri.EscapeDataString(user.Id)}" +
                                   $"&provider=telegram";
            
            return new RedirectResult(finalRedirectUrl);
        }

        public class TelegramTokenResponse
        {
            [JsonPropertyName("access_token")]
            public string AccessToken { get; set; } = string.Empty;

            [JsonPropertyName("id_token")]
            public string IdToken { get; set; } = string.Empty;

            [JsonPropertyName("token_type")]
            public string TokenType { get; set; } = string.Empty;

            [JsonPropertyName("expires_in")]
            public int ExpiresIn { get; set; }
        }
    }
}
