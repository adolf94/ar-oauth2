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

        public string GenerateAccessToken(User user, Client client, string scopes)
        {
            var key = _rsaKeyService.GetSigningKey();

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub,   user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti,   Guid.NewGuid().ToString()),
                new Claim("client_id", client.ClientId),
                new Claim("scope",     scopes)
            };

            foreach (var role in user.Roles)
                claims.Add(new Claim(ClaimTypes.Role, role));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(5),
                Issuer = Issuer,
                Audience = client.ClientId,
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
            };

            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(handler.CreateToken(tokenDescriptor));
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

        public async Task<string> GenerateRefreshTokenAsync(string userId, string clientId)
        {
            var token = new Token
            {
                Id = Guid.NewGuid().ToString().Replace("-", ""),
                UserId = userId,
                ClientId = clientId,
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

        public async Task<string> RotateRefreshTokenAsync(Token oldToken)
        {
            // Remove the old token (one-time use)
            _dbContext.Tokens.Remove(oldToken);

            // Generate a fresh one
            return await GenerateRefreshTokenAsync(oldToken.UserId, oldToken.ClientId);
        }

        // ── ID Token ────────────────────────────────────────────────

        public string GenerateIdToken(User user, Client client, string nonce = "")
        {
            var key = _rsaKeyService.GetSigningKey();

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub,   user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti,   Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat,   DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim("nonce", nonce)
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1),
                Issuer = Issuer,
                Audience = client.ClientId,
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
            };

            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(handler.CreateToken(tokenDescriptor));
        }
    }
}
