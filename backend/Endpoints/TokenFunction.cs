using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using backend.DTOs;
using backend.Services;
using System.Text.Json;
using System.IO;

namespace backend.Endpoints
{
    public class TokenFunction
    {
        private readonly ILogger<TokenFunction> _logger;
        private readonly IAuthCodeService _authCodeService;
        private readonly ITokenService _tokenService;
        private readonly IUserService _userService;
        private readonly IClientService _clientService;

        public TokenFunction(
            ILogger<TokenFunction> logger,
            IAuthCodeService authCodeService,
            ITokenService tokenService,
            IUserService userService,
            IClientService clientService)
        {
            _logger = logger;
            _authCodeService = authCodeService;
            _tokenService = tokenService;
            _userService = userService;
            _clientService = clientService;
        }

        [Function("Token")]
        public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "api/token")] HttpRequest req)
        {
            _logger.LogInformation("Token endpoint invoked.");

            // Support both JSON and application/x-www-form-urlencoded bodies
            TokenRequest? tokenReq = null;

            var contentType = req.ContentType ?? string.Empty;
            if (contentType.Contains("application/x-www-form-urlencoded"))
            {
                var form = await req.ReadFormAsync();
                tokenReq = new TokenRequest
                {
                    grant_type    = form["grant_type"].ToString()    ?? string.Empty,
                    code          = form["code"].ToString()          ?? string.Empty,
                    client_id     = form["client_id"].ToString()     ?? string.Empty,
                    client_secret = form["client_secret"].ToString() ?? string.Empty,
                    redirect_uri  = form["redirect_uri"].ToString()  ?? string.Empty,
                    code_verifier = form["code_verifier"].ToString() ?? string.Empty,
                    refresh_token = form["refresh_token"].ToString() ?? string.Empty,
                    scope         = form["scope"].ToString()         ?? string.Empty
                };
            }
            else
            {
                var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
                tokenReq = JsonSerializer.Deserialize<TokenRequest>(requestBody, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }

            if (tokenReq == null)
                return new BadRequestObjectResult(new { error = "invalid_request" });

            // ── authorization_code grant ────────────────────────────────────────────
            if (tokenReq.grant_type == "authorization_code")
            {
                var validCode = await _authCodeService.ValidateAuthCodeAsync(
                    tokenReq.code, tokenReq.client_id, tokenReq.redirect_uri, tokenReq.code_verifier);

                if (validCode == null)
                    return new UnauthorizedObjectResult(new { error = "invalid_grant", error_description = "Authorization code is invalid or expired." });

                var user   = await _userService.GetByIdAsync(validCode.UserId);
                var client = await _clientService.GetByClientIdAsync(tokenReq.client_id);

                if (user == null || client == null)
                    return new UnauthorizedObjectResult(new { error = "invalid_grant", error_description = "User or client not found." });

                // Multi-tier Client Secret Validation:
                if (client.ClientSecrets != null && client.ClientSecrets.Any())
                {
                    // Confidential Client: MUST provide a valid secret
                    if (string.IsNullOrEmpty(tokenReq.client_secret) || !_clientService.VerifyClientSecret(tokenReq.client_secret, client.ClientSecrets))
                    {
                        return new UnauthorizedObjectResult(new { error = "invalid_client", error_description = "Client authentication failed." });
                    }
                }
                else
                {
                    // Public Client: MUST use PKCE
                    _logger.LogInformation("Client {ClientId} is public; requiring PKCE validation.", client.ClientId);
                    if (string.IsNullOrEmpty(validCode.CodeChallenge))
                    {
                        return new UnauthorizedObjectResult(new { error = "invalid_client", error_description = "Public clients must use PKCE." });
                    }
                }

                var sid = Guid.NewGuid().ToString();
                
                var scopesToUse = validCode.Scopes;
                if (!string.IsNullOrEmpty(tokenReq.scope))
                {
                    var requestedScopes = tokenReq.scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    var authorizedByCode = validCode.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
                    
                    var verifiedScopes = new List<string>();
                    foreach (var s in requestedScopes)
                    {
                        if (authorizedByCode.Contains(s) || await _tokenService.IsScopeAuthorizedAsync(user, client, s))
                        {
                            verifiedScopes.Add(s);
                        }
                        else
                        {
                            return new BadRequestObjectResult(new { error = "invalid_scope", error_description = $"The scope '{s}' is not allowed for this client or user." });
                        }
                    }
                    scopesToUse = string.Join(' ', verifiedScopes.Distinct());
                    _logger.LogInformation("Using specific scopes for access token: {Scopes}", scopesToUse);
                }

                var (accessToken, grantedScopes) = await _tokenService.GenerateAccessToken(user, client, scopesToUse, sid: sid);
                var refreshToken = await _tokenService.GenerateRefreshTokenAsync(user.Id, client.ClientId, validCode.Scopes, sid: sid);
                
                string? idToken = null;
                if (scopesToUse.Contains("openid"))
                {
                   idToken = _tokenService.GenerateIdToken(user, client, nonce: "", sid: sid);
                }


                return new OkObjectResult(new TokenResponse
                {
                    AccessToken  = accessToken,
                    IdToken      = idToken,
                    ExpiresIn    = 300,
                    RefreshToken = refreshToken,
                    TokenType    = "Bearer",
                    Scope        = grantedScopes
                });
            }

            // ── refresh_token grant ─────────────────────────────────────────────────
            if (tokenReq.grant_type == "refresh_token")
            {
                if (string.IsNullOrEmpty(tokenReq.refresh_token) || string.IsNullOrEmpty(tokenReq.client_id))
                    return new BadRequestObjectResult(new { error = "invalid_request", error_description = "refresh_token and client_id are required." });

                var storedToken = await _tokenService.ValidateRefreshTokenAsync(tokenReq.refresh_token, tokenReq.client_id);
                if (storedToken == null)
                    return new UnauthorizedObjectResult(new { error = "invalid_grant", error_description = "Refresh token is invalid or expired." });

                var user   = await _userService.GetByIdAsync(storedToken.UserId);
                var client = await _clientService.GetByClientIdAsync(tokenReq.client_id);

                if (user == null || client == null)
                    return new UnauthorizedObjectResult(new { error = "invalid_grant", error_description = "User or client not found." });

                // Secret Validation for Refresh Token
                if (client.ClientSecrets != null && client.ClientSecrets.Any())
                {
                    if (string.IsNullOrEmpty(tokenReq.client_secret) || !_clientService.VerifyClientSecret(tokenReq.client_secret, client.ClientSecrets))
                    {
                        return new UnauthorizedObjectResult(new { error = "invalid_client", error_description = "Client authentication failed." });
                    }
                }
                else
                {
                    _logger.LogInformation("Client {ClientId} is public; skipping secret validation for refresh_token.", client.ClientId);
                }

                var sid = storedToken.Sid;
                if (string.IsNullOrEmpty(sid)) sid = Guid.NewGuid().ToString();

                var scopesToUse = storedToken.Scopes;
                if (!string.IsNullOrEmpty(tokenReq.scope))
                {
                    var requestedScopes = tokenReq.scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    var authorizedByToken = storedToken.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
                    
                    var verifiedScopes = new List<string>();
                    foreach (var s in requestedScopes)
                    {
                        if (authorizedByToken.Contains(s) || await _tokenService.IsScopeAuthorizedAsync(user, client, s))
                        {
                            verifiedScopes.Add(s);
                        }
                        else
                        {
                            return new BadRequestObjectResult(new { error = "invalid_scope", error_description = $"The scope '{s}' is not allowed for this client or user." });
                        }
                    }
                    scopesToUse = string.Join(' ', verifiedScopes.Distinct());
                    _logger.LogInformation("Using specific scopes for refresh-based access token: {Scopes}", scopesToUse);
                }

                var (newAccessToken, grantedScopes) = await _tokenService.GenerateAccessToken(user, client, scopesToUse, sid: sid);
                var newRefreshToken = await _tokenService.RotateRefreshTokenAsync(storedToken, sid: sid);


                string? idToken = null;
                if (grantedScopes != null && grantedScopes.Contains("openid"))
                {
                   idToken = _tokenService.GenerateIdToken(user, client, nonce: "", sid: sid);
                }


                return new OkObjectResult(new TokenResponse
                {
                    AccessToken  = newAccessToken,
                    IdToken      = idToken,
                    ExpiresIn    = 300,
                    RefreshToken = newRefreshToken,
                    TokenType    = "Bearer",
                    Scope        = grantedScopes
                });
            }

            // ── client_credentials grant ────────────────────────────────────────────
            if (tokenReq.grant_type == "client_credentials")
            {
                var client = await _clientService.GetByClientIdAsync(tokenReq.client_id);
                if (client == null)
                    return new UnauthorizedObjectResult(new { error = "invalid_client" });

                // Secret Validation is Mandatory for client_credentials
                if (client.ClientSecrets == null || !client.ClientSecrets.Any())
                {
                    return new UnauthorizedObjectResult(new { error = "invalid_client", error_description = "Client has no secrets configured." });
                }

                if (string.IsNullOrEmpty(tokenReq.client_secret) || !_clientService.VerifyClientSecret(tokenReq.client_secret, client.ClientSecrets))
                {
                    return new UnauthorizedObjectResult(new { error = "invalid_client", error_description = "Client authentication failed." });
                }

                var (accessToken, grantedScopes) = await _tokenService.GenerateClientAccessToken(client, tokenReq.scope);

                return new OkObjectResult(new TokenResponse
                {
                    AccessToken = accessToken,
                    ExpiresIn   = 3600, // 1 hour for machine tokens
                    TokenType   = "Bearer",
                    Scope       = grantedScopes
                });
            }

            return new BadRequestObjectResult(new { error = "unsupported_grant_type" });
        }
    }
}
