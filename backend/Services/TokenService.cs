using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using backend.Data;
using backend.Models;
using Microsoft.IdentityModel.Tokens;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace backend.Services
{
    public class TokenService : ITokenService
    {
        private readonly AppDbContext _dbContext;
        private readonly IRsaKeyService _rsaKeyService;
        private readonly Configuration.AppConfig _appConfig;
        private readonly IDbHelper _dbHelper;

        public TokenService(AppDbContext dbContext, IRsaKeyService rsaKeyService, Configuration.AppConfig appConfig, IDbHelper dbHelper)
        {
            _dbContext = dbContext;
            _rsaKeyService = rsaKeyService;
            _appConfig = appConfig;
            _dbHelper = dbHelper;
        }

        private string Issuer => _appConfig.Jwt.Issuer;

        // ── Access Token ────────────────────────────────────────────

        public async Task<(string Token, string Scopes)> GenerateAccessToken(User user, Client client, string scopes, string? sid = null)
        {
            var key = _rsaKeyService.GetSigningKey();

            // 0. Fetch scope definitions to verify Client-Only restriction
            var clientScopes = await _dbContext.ApplicationScopes
                .Where(s => s.ClientId == client.ClientId)
                .ToListAsync();

            // Filter out any Client-Only scopes (User sessions cannot carry client-only permissions)
            var finalScopesList = scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Where(s => !clientScopes.Any(cs => (cs.Name == s || cs.FullScopeName == s) && cs.IsClientOnly == true))
                .ToList();
            
            // 1. Resolve and Validate Cross-App Scopes
            var qualifiedScopes = finalScopesList.Where(s => s.StartsWith("api://")).ToList();
            var validatedCrossScopes = new List<string>();

            if (qualifiedScopes.Any())
            {
                var trusts = await _dbContext.CrossAppTrusts
                    .Where(t => t.RequestingClientId == client.ClientId && t.IsApproved)
                    .ToListAsync();

                foreach (var qs in qualifiedScopes)
                {
                    // Find if current client is trusted to request this specific scope
                    var trust = trusts.FirstOrDefault(t => t.Matches(qs));
                    if (trust != null)
                    {
                        // Now check if USER has this scope assigned for the TargetClient (or if it is AdminApproved for TargetClient)
                        var isUserAuthorized = await _dbContext.UserClientScopes
                            .Where(ucs => ucs.UserId == user.Id && ucs.ClientId == trust.TargetClientId && ucs.Scope == trust.ScopeName)
                            .FirstOrDefaultAsync() != null;
                        
                        if (!isUserAuthorized)
                        {
                            isUserAuthorized = await _dbContext.ApplicationScopes
                                .Where(s => s.ClientId == trust.TargetClientId && s.Name == trust.ScopeName && s.IsClientOnly == true)
                                .FirstOrDefaultAsync() != null;
                        }

                        // Admin Bypass: If user is a global admin, they are authorized for any trusted cross-app scope
                        if (!isUserAuthorized && user.Roles.Contains("admin"))
                        {
                            isUserAuthorized = true;
                        }

                        if (isUserAuthorized)
                        {
                            validatedCrossScopes.Add(qs);
                        }
                    }
                }
            }

            // Remove all qualified scopes that weren't validated
            finalScopesList.RemoveAll(s => s.StartsWith("api://") && !validatedCrossScopes.Contains(s));

            var adminApprovedScopes = clientScopes.Where(s => s.IsAdminApproved == true).Select(s => s.FullScopeName).ToList();

            // Include Admin Approved scopes in the user session
            foreach (var s in adminApprovedScopes)
            {
                if (!finalScopesList.Contains(s))
                    finalScopesList.Add(s);
            }

            var finalScopesString = string.Join(' ', finalScopesList.Distinct());

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub,   user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Name,  user.Name),
                new Claim(JwtRegisteredClaimNames.Jti,   Guid.NewGuid().ToString()),
                new Claim("client_id", client.ClientId),
                new Claim("scope",     finalScopesString)
            };

            if (!string.IsNullOrEmpty(user.Picture))
            {
                claims.Add(new Claim("picture", user.Picture));
            }

            // Linking ID Token for single logout via session ID
            if (!string.IsNullOrEmpty(sid))
            {
                claims.Add(new Claim("sid", sid));
            }


            // 1. Global Roles
            foreach (var role in user.Roles)
                claims.Add(new Claim(ClaimTypes.Role, role));

            // 2. App-Specific Scopes (Manual User-level assignments)
            var userLevelScopes = await _dbContext.UserClientScopes
                .Where(ucs => ucs.UserId == user.Id && ucs.ClientId == client.ClientId)
                .Select(ucs => ucs.Scope)
                .ToListAsync();

            foreach (var scope in userLevelScopes)
            {
                // Verify this is not a Client-Only scope (those cannot be applied to users)
                var isClientOnly = clientScopes.Any(s => (s.Name == scope || s.FullScopeName == scope) && s.IsClientOnly == true);
                if (!isClientOnly)
                {
                    claims.Add(new Claim(ClaimTypes.Role, scope));
                }
            }

            // 3. Admin Approved Scopes as Roles (Auto-granted to users)
            foreach (var scope in adminApprovedScopes)
            {
                if (!claims.Any(c => c.Type == ClaimTypes.Role && c.Value == scope))
                    claims.Add(new Claim(ClaimTypes.Role, scope));
            }

            // 4. Validated Cross-App Scopes as Roles
            foreach (var scope in validatedCrossScopes)
            {
                if (!claims.Any(c => c.Type == ClaimTypes.Role && c.Value == scope))
                    claims.Add(new Claim(ClaimTypes.Role, scope));
            }

            // 5. Build Audiences list (Requesting Client + Target Clients for cross-app scopes)
            var audiences = new List<string> { client.ClientId };
            foreach (var vs in validatedCrossScopes)
            {
                var targetId = vs.Substring(6).Split('/')[0];
                if (!audiences.Contains(targetId))
                    audiences.Add(targetId);
            }

            foreach (var aud in audiences)
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Aud, aud));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(5),
                Issuer = Issuer,
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
            };

            var handler = new JwtSecurityTokenHandler();
            return (handler.WriteToken(handler.CreateToken(tokenDescriptor)), finalScopesString);
        }

        // ── Client Access Token (Machine-to-Machine) ────────────────

        public async Task<(string Token, string Scopes)> GenerateClientAccessToken(Client client, string requestedScopes)
        {
            var key = _rsaKeyService.GetSigningKey();
            
            // Fetch and map in-memory to avoid translation issue with FullScopeName computed property
            var clientOnlyScopes = (await _dbContext.ApplicationScopes
                .Where(s => s.ClientId == client.ClientId && s.IsClientOnly == true)
                .Select(s => new { s.ClientId, s.Name })
                .ToListAsync())
                .Select(s => $"api://{s.ClientId}/{s.Name}")
                .ToList();

            // 2. Fetch Cross-App Trusts and their associated IsClientOnly scopes
            var trusts = await _dbContext.CrossAppTrusts
                .Where(t => t.RequestingClientId == client.ClientId && t.IsApproved)
                .ToListAsync();

            var allowedCrossAppScopes = new List<string>();
            if (trusts.Any())
            {
                var targetClientIds = trusts.Select(t => t.TargetClientId).Distinct().ToList();
                var targetScopes = await _dbContext.ApplicationScopes
                    .Where(s => targetClientIds.Contains(s.ClientId) && s.IsClientOnly == true)
                    .ToListAsync();

                foreach (var trust in trusts)
                {
                    if (targetScopes.Any(s => s.ClientId == trust.TargetClientId && s.Name == trust.ScopeName))
                    {
                        allowedCrossAppScopes.Add($"api://{trust.TargetClientId}/{trust.ScopeName}");
                    }
                }
            }

            var allAllowedScopes = clientOnlyScopes.Concat(allowedCrossAppScopes).ToList();

            var finalScopesList = new List<string>();
            if (string.IsNullOrEmpty(requestedScopes))
            {
                // If no specific scopes requested, grant all allowed Client-Only scopes (including trusted cross-app ones)
                finalScopesList.AddRange(allAllowedScopes);
            }
            else
            {
                var requestedList = requestedScopes.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                foreach (var s in requestedList)
                {
                    if (allAllowedScopes.Contains(s))
                        finalScopesList.Add(s);
                }
            }

            var finalScopesString = string.Join(' ', finalScopesList.Distinct());

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub,   client.ClientId), // Subject is title of the client itself
                new Claim(JwtRegisteredClaimNames.Jti,   Guid.NewGuid().ToString()),
                new Claim("client_id",                   client.ClientId),
                new Claim("scope",                       finalScopesString),
                new Claim("grant_type",                  "client_credentials")
            };

            // Add all assigned scopes as roles for the client principal
            foreach (var scope in finalScopesList)
            {
                claims.Add(new Claim(ClaimTypes.Role, scope));
            }

            // Build Audiences list (Requesting Client + Target Clients for cross-app scopes)
            var audiences = new List<string> { client.ClientId };
            foreach (var fs in finalScopesList)
            {
                if (fs.StartsWith("api://"))
                {
                    var targetId = fs.Substring(6).Split('/')[0];
                    if (!audiences.Contains(targetId))
                        audiences.Add(targetId);
                }
            }

            foreach (var aud in audiences)
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Aud, aud));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1),
                Issuer = Issuer,
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
            };

            var handler = new JwtSecurityTokenHandler();
            return (handler.WriteToken(handler.CreateToken(tokenDescriptor)), finalScopesString);
        }

        public ClaimsPrincipal? ValidateAccessToken(string jwt, string? audience = null)
        {
            var keys = _rsaKeyService.GetValidationKeys();
            var handler = new JwtSecurityTokenHandler();

            try
            {
                var tvp = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = keys,
                    ValidateIssuer = true,
                    ValidIssuer = Issuer,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,
                    ValidateAudience = audience != null,
                };
                if (audience != null) tvp.ValidAudience = audience;

                return handler.ValidateToken(jwt, tvp, out _);
            }
            catch
            {
                return null;
            }
        }

        // ── Refresh Token ───────────────────────────────────────────

        public async Task<string> GenerateRefreshTokenAsync(string userId, string clientId, string scopes, string? sid = null)
        {
            var token = new Token
            {
                Id = Guid.NewGuid().ToString().Replace("-", ""),
                Sid = sid ?? string.Empty,
                UserId = userId,
                ClientId = clientId,
                Scopes = scopes,
                ExpiresAt = DateTime.UtcNow.AddDays(30)
            };

            _dbContext.Tokens.Add(token);
            await _dbHelper.SaveChangesAsync();

            return token.Id;
        }

        public async Task<Token?> ValidateRefreshTokenAsync(string tokenValue, string clientId)
        {
            var token = await _dbContext.Tokens
                .FirstOrDefaultAsync(t => t.Id == tokenValue && t.ClientId == clientId);

            if (token == null || token.ExpiresAt < DateTime.UtcNow)
                return null;

            return token;
        }

        public async Task<string> RotateRefreshTokenAsync(Token oldToken, string? sid = null)
        {
            // Remove the old token (one-time use)
            _dbContext.Tokens.Remove(oldToken);

            // Generate a fresh one, preserving scopes and relational ID
            return await GenerateRefreshTokenAsync(oldToken.UserId, oldToken.ClientId, oldToken.Scopes, sid ?? oldToken.Sid);
        }

        // ── ID Token ────────────────────────────────────────────────

        public string GenerateIdToken(User user, Client client, string nonce = "", string? sid = null)
        {
            var key = _rsaKeyService.GetSigningKey();

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub,   user.Id),
                new Claim(JwtRegisteredClaimNames.Name, user.Name),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti,   Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat,   DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim("nonce", nonce)
            };

            if (!string.IsNullOrEmpty(user.Picture))
            {
                claims.Add(new Claim("picture", user.Picture));
            }

            if (!string.IsNullOrEmpty(sid))
            {
                claims.Add(new Claim("sid", sid));
            }



            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(30),
                Issuer = Issuer,
                Audience = client.ClientId,
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
            };

            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(handler.CreateToken(tokenDescriptor));
        }
        public async Task<bool> IsScopeAuthorizedAsync(User user, Client client, string scope)
        {
            if (scope == "openid" || scope == "profile" || scope == "email" || scope == "offline_access")
                return true;

            if (scope.StartsWith("api://"))
            {
                var trusts = await _dbContext.CrossAppTrusts
                    .Where(t => t.RequestingClientId == client.ClientId && t.IsApproved)
                    .ToListAsync();

                var trust = trusts.FirstOrDefault(t => t.Matches(scope));
                if (trust == null) return false;

                var isUserAuthorized = await _dbContext.UserClientScopes
                    .Where(ucs => ucs.UserId == user.Id && ucs.ClientId == trust.TargetClientId && ucs.Scope == trust.ScopeName)
                    .FirstOrDefaultAsync() != null;

                if (!isUserAuthorized)
                {
                    isUserAuthorized = await _dbContext.ApplicationScopes
                        .Where(s => s.ClientId == trust.TargetClientId && s.Name == trust.ScopeName && s.IsClientOnly == true)
                        .FirstOrDefaultAsync() != null;
                }

                if (!isUserAuthorized && user.Roles.Contains("admin"))
                {
                    isUserAuthorized = true;
                }

                return isUserAuthorized;
            }
            else
            {
                // 1. Check if the scope is Client-Only (Bypass user logic)
                // Avoid using FullScopeName in DB query as it's not mapped
                var isClientOnly = await _dbContext.ApplicationScopes
                    .Where(s => s.ClientId == client.ClientId && s.Name == scope && s.IsClientOnly == true)
                    .FirstOrDefaultAsync() != null;
                if (isClientOnly) return true;

                // 2. Check User-specific assignments
                var isAuthorized = await _dbContext.UserClientScopes
                    .AnyAsync(ucs => ucs.UserId == user.Id && ucs.ClientId == client.ClientId && ucs.Scope == scope);

                // 3. Fallback to Admin-Approved scopes for users
                if (!isAuthorized)
                {
                    isAuthorized = await _dbContext.ApplicationScopes
                        .Where(s => s.ClientId == client.ClientId && s.Name == scope && s.IsAdminApproved == true)
                        .FirstOrDefaultAsync() != null;
                }

                return isAuthorized;
            }
        }

        // ── Session Token (Internal ar-auth session) ────────────────

        public string GenerateSessionToken(User user)
        {
            var key = _rsaKeyService.GetSigningKey();

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Name, user.Name ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("type", "session")
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(30), // Persistent session
                Issuer = Issuer,
                Audience = Issuer, // Internal audience
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
            };

            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(handler.CreateToken(tokenDescriptor));
        }

        public ClaimsPrincipal? ValidateSessionToken(string token)
        {
            var keys = _rsaKeyService.GetValidationKeys();
            var handler = new JwtSecurityTokenHandler();

            try
            {
                var tvp = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = keys,
                    ValidateIssuer = true,
                    ValidIssuer = Issuer,
                    ValidateAudience = true,
                    ValidAudience = Issuer,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                var principal = handler.ValidateToken(token, tvp, out _);
                if (principal.FindFirst("type")?.Value != "session") return null;

                return principal;
            }
            catch
            {
                return null;
            }
        }

        public string GenerateLinkToken(string telegramId, string clientId, string requestorId)
        {
            var key = _rsaKeyService.GetSigningKey();
            var claims = new List<Claim>
            {
                new Claim("telegram_id", telegramId),
                new Claim("client_id", clientId),
                new Claim("requestor_id", requestorId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("type", "link")
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(15),
                Issuer = Issuer,
                Audience = Issuer,
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
            };

            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(handler.CreateToken(tokenDescriptor));
        }

        public ClaimsPrincipal? ValidateLinkToken(string token)
        {
            var keys = _rsaKeyService.GetValidationKeys();
            var handler = new JwtSecurityTokenHandler();

            try
            {
                var tvp = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = keys,
                    ValidateIssuer = true,
                    ValidIssuer = Issuer,
                    ValidateAudience = true,
                    ValidAudience = Issuer,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                var principal = handler.ValidateToken(token, tvp, out _);
                if (principal.FindFirst("type")?.Value != "link") return null;

                return principal;
            }
            catch
            {
                return null;
            }
        }
    }
}
