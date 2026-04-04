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
        private readonly IAuthCodeService _authCodeService;
        private readonly IUserService _userService;
        private readonly IClientService _clientService;
        private readonly Configuration.AppConfig _appConfig;
        private readonly IRsaKeyService _rsaKeyService;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ITokenService _tokenService;

        private const string RelayStateCookieName = "tg_relay_state";

        public TelegramOAuthFunction(
            ILogger<TelegramOAuthFunction> logger,
            IAuthCodeService authCodeService,
            IUserService userService,
            IClientService clientService,
            Configuration.AppConfig appConfig,
            IRsaKeyService rsaKeyService,
            IHttpClientFactory httpClientFactory,
            ITokenService tokenService)
        {
            _logger = logger;
            _authCodeService = authCodeService;
            _userService = userService;
            _clientService = clientService;
            _appConfig = appConfig;
            _rsaKeyService = rsaKeyService;
            _httpClientFactory = httpClientFactory;
            _tokenService = tokenService;
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

            // Determine which Telegram Bot to use (Client-specific or System Default)
            var client = await _clientService.GetByClientIdAsync(clientId);
            var botToken = !string.IsNullOrEmpty(client?.TelegramBotClientSecret) 
                ? client.TelegramBotClientSecret 
                : _appConfig.Telegram.ClientSecret;
            
            var botId = !string.IsNullOrEmpty(client?.TelegramBotClientId)
                ? client.TelegramBotClientId
                : _appConfig.Telegram.ClientId;

            if (string.IsNullOrEmpty(botId) && !string.IsNullOrEmpty(botToken))
            {
                // Extract bot ID from token (it's the numeric part before the first colon)
                var colonIndex = botToken.IndexOf(':');
                if (colonIndex > 0)
                {
                    botId = botToken.Substring(0, colonIndex);
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

            var client = await _clientService.GetByClientIdAsync(spClientId);
            var botToken = !string.IsNullOrEmpty(client?.TelegramBotClientSecret) 
                ? client.TelegramBotClientSecret 
                : _appConfig.Telegram.ClientSecret;
            
            var botId = !string.IsNullOrEmpty(client?.TelegramBotClientId)
                ? client.TelegramBotClientId
                : _appConfig.Telegram.ClientId;

            if (string.IsNullOrEmpty(botId) && !string.IsNullOrEmpty(botToken))
            {
                var colonIndex = botToken.IndexOf(':');
                if (colonIndex > 0)
                {
                    botId = botToken.Substring(0, colonIndex);
                }
            }

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
            var claims = idTokenJson.Claims.ToList();

            var telegramSub = idTokenJson.Subject; // 'sub' claim
            var telegramId = claims.FirstOrDefault(c => c.Type == "id")?.Value ?? telegramSub;
            var telegramEmail = claims.FirstOrDefault(c => c.Type == "email")?.Value;
            var telegramPhone = claims.FirstOrDefault(c => c.Type == "phone_number")?.Value;
            var telegramFirstName = claims.FirstOrDefault(c => c.Type == "given_name")?.Value;
            var telegramLastName = claims.FirstOrDefault(c => c.Type == "family_name")?.Value;
            var telegramName = claims.FirstOrDefault(c => c.Type == "name")?.Value 
                  ?? (string.IsNullOrEmpty(telegramLastName) ? telegramFirstName : $"{telegramFirstName} {telegramLastName}");
            var telegramPhotoUrl = claims.FirstOrDefault(c => c.Type == "picture")?.Value;

            // 4. Map Telegram User
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
                        await _userService.LinkExternalIdentityAsync(targetUserId, "telegram", telegramId, telegramSub, telegramName, telegramEmail, telegramPhone, telegramPhotoUrl);
                        user = await _userService.GetByIdAsync(targetUserId);
                    }
                } catch (Exception ex) {
                    _logger.LogWarning(ex, "Invalid link_token in Telegram callback.");
                }
            }

            if (user == null)
            {
                // Fallback: Check by real email (if provided)
                if (!string.IsNullOrEmpty(telegramEmail))
                {
                    user = await _userService.GetByEmailAsync(telegramEmail);
                }

                if (user == null)
                {
                    _logger.LogInformation("Creating new Telegram user with Id {Id} and Sub {Sub}", telegramId, telegramSub);
                    user = await _userService.CreateUserAsync(telegramEmail ?? string.Empty, telegramPhone, new List<string> { "unregistered" }, "telegram", telegramId, telegramName, telegramSub, telegramEmail, telegramPhone, telegramPhotoUrl);
                }
                else
                {
                    // If user found by email, link the telegram identity
                    _logger.LogInformation("Found existing user by email {Email}, linking Telegram {Id}", user.Email, telegramId);
                    await _userService.LinkExternalIdentityAsync(user.Id, "telegram", telegramId, telegramSub, telegramName, telegramEmail, telegramPhone, telegramPhotoUrl);
                }
            }

            // Sync user details from Telegram (stores everything in ExternalIdentities + some top-level sync)
            await _userService.UpdateExternalIdentityDetailsAsync(user.Id, "telegram", telegramId, telegramSub, telegramName, telegramEmail, telegramPhone, telegramPhotoUrl);
            user = await _userService.GetByIdAsync(user.Id) ?? user; // Refresh local user object

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

            // 7. Set active session cookie (HttpOnly/Secure)
            var sessionToken = _tokenService.GenerateSessionToken(user);
            AuthHelper.SetSessionCookie(req.HttpContext.Response, sessionToken);

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
