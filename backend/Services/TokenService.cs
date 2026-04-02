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
    public class TokenService
    {
        private readonly AppDbContext _dbContext;
        private readonly RsaKeyService _rsaKeyService;
        private readonly Configuration.AppConfig _appConfig;

        public TokenService(AppDbContext dbContext, RsaKeyService rsaKeyService, Configuration.AppConfig appConfig)
        {
            _dbContext = dbContext;
            _rsaKeyService = rsaKeyService;
            _appConfig = appConfig;
        }

        private string Issuer => _appConfig.Jwt.Issuer;

        // ── Access Token ────────────────────────────────────────────

        public async Task<(string Token, string Scopes)> GenerateAccessToken(User user, Client client, string scopes, string? sid = null)
        {
            var key = _rsaKeyService.GetSigningKey();

            var finalScopesList = scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
            
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
                                .Where(s => s.ClientId == trust.TargetClientId && s.Name == trust.ScopeName && s.IsAdminApproved)
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

            // 2. Fetch Admin Approved (Auto-granted) scopes for the Requesting Client
            var autoGrantedScopes = await _dbContext.ApplicationScopes
                .Where(s => s.ClientId == client.ClientId && s.IsAdminApproved)
                .Select(s => s.FullScopeName)
                .ToListAsync();

            foreach (var s in autoGrantedScopes)
            {
                if (!finalScopesList.Contains(s))
                    finalScopesList.Add(s);
            }

            var finalScopesString = string.Join(' ', finalScopesList.Distinct());

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub,   user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti,   Guid.NewGuid().ToString()),
                new Claim("client_id", client.ClientId),
                new Claim("scope",     finalScopesString)
            };

            // Linking ID Token for single logout via session ID
            if (!string.IsNullOrEmpty(sid))
            {
                claims.Add(new Claim("sid", sid));
            }

            // 1. Global Roles
            foreach (var role in user.Roles)
                claims.Add(new Claim(ClaimTypes.Role, role));

            // 2. App-Specific Scopes (Manual Assignments for current app)
            var appSpecificScopes = await _dbContext.UserClientScopes
                .Where(ucs => ucs.UserId == user.Id && ucs.ClientId == client.ClientId)
                .Select(ucs => ucs.Scope)
                .ToListAsync();

            foreach (var scope in appSpecificScopes)
                claims.Add(new Claim(ClaimTypes.Role, scope));

            // 3. App-Specific Scopes (Auto-granted for current app)
            foreach (var scope in autoGrantedScopes)
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
            await _dbContext.SaveChangesAsync();

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
                    .AnyAsync(ucs => ucs.UserId == user.Id && ucs.ClientId == trust.TargetClientId && ucs.Scope == trust.ScopeName);

                if (!isUserAuthorized)
                {
                    isUserAuthorized = await _dbContext.ApplicationScopes
                        .AnyAsync(s => s.ClientId == trust.TargetClientId && s.Name == trust.ScopeName && s.IsAdminApproved);
                }

                if (!isUserAuthorized && user.Roles.Contains("admin"))
                {
                    isUserAuthorized = true;
                }

                return isUserAuthorized;
            }
            else
            {
                var isAuthorized = await _dbContext.UserClientScopes
                    .AnyAsync(ucs => ucs.UserId == user.Id && ucs.ClientId == client.ClientId && ucs.Scope == scope);

                if (!isAuthorized)
                {
                    isAuthorized = await _dbContext.ApplicationScopes
                        .AnyAsync(s => s.ClientId == client.ClientId && (s.Name == scope || s.FullScopeName == scope) && s.IsAdminApproved);
                }

                return isAuthorized;
            }
        }
    }
}
