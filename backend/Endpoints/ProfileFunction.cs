using System;
using System.IO;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using backend.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace backend.Endpoints
{
    public class ProfileFunction
    {
        private readonly ILogger<ProfileFunction> _logger;
        private readonly IUserService _userService;
        private readonly ITokenService _tokenService;
        private readonly IRsaKeyService _rsaKeyService;

        public ProfileFunction(ILogger<ProfileFunction> logger, IUserService userService, ITokenService tokenService, IRsaKeyService rsaKeyService)
        {
            _logger = logger;
            _userService = userService;
            _tokenService = tokenService;
            _rsaKeyService = rsaKeyService;
        }

        [Function("GetProfile")]
        public async Task<IActionResult> GetProfile(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "api/profile")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateToken(req, _tokenService, _logger);
            if (error != null) return error;

            var userId = principal!.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return new UnauthorizedObjectResult(new { error = "invalid_token_claims" });
            }

            var user = await _userService.GetByIdAsync(userId);
            if (user == null)
            {
                return new NotFoundResult();
            }

            return new OkObjectResult(new
            {
                user.Id,
                user.Email,
                user.Name,
                user.Picture,
                user.MobileNumber,
                user.Roles,
                ExternalIdentities = user.ExternalIdentities.Select(i => new {
                    i.Provider,
                    i.ProviderId,
                    i.Sub,
                    i.Name,
                    i.Email,
                    i.MobileNumber,
                    i.PhotoUrl
                }).ToList()
            });
        }

        [Function("CreateLinkToken")]
        public async Task<IActionResult> CreateLinkToken(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "api/profile/link-token")] HttpRequest req)
        {
            await Task.Yield();
            var (principal, error) = AuthHelper.ValidateToken(req, _tokenService, _logger);
            if (error != null) return error;

            var userId = principal!.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return new UnauthorizedObjectResult(new { error = "invalid_token_claims" });
            }

            // Create a short-lived link token
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = _rsaKeyService.GetSigningKey();

            var claims = new List<Claim>
            {
                new Claim("link_user_id", userId),
                new Claim("type", "link_account")
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(5),
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
            };

            var token = tokenHandler.WriteToken(tokenHandler.CreateToken(tokenDescriptor));
            return new OkObjectResult(new { link_token = token });
        }
    }
}
