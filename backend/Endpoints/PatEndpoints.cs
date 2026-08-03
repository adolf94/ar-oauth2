using System;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using backend.Data;
using backend.Models;
using backend.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace backend.Endpoints
{
    public class PatEndpoints
    {
        private readonly ILogger<PatEndpoints> _logger;
        private readonly AppDbContext _dbContext;
        private readonly ITokenService _tokenService;
        private readonly IUserService _userService;

        public PatEndpoints(
            ILogger<PatEndpoints> logger,
            AppDbContext dbContext,
            ITokenService tokenService,
            IUserService userService)
        {
            _logger = logger;
            _dbContext = dbContext;
            _tokenService = tokenService;
            _userService = userService;
        }

        public class CreatePatRequest
        {
            public string Name { get; set; } = string.Empty;
            public string Scopes { get; set; } = string.Empty;
            public int? ExpiresInDays { get; set; }
        }

        [Function("CreatePat")]
        public async Task<IActionResult> CreatePat(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "api/pat/create")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateToken(req, _tokenService, _logger);
            if (error != null) return error;

            var userId = principal!.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return new UnauthorizedObjectResult(new { error = "invalid_token_claims" });
            }

            var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            var body = JsonSerializer.Deserialize<CreatePatRequest>(requestBody, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (body == null || string.IsNullOrWhiteSpace(body.Name))
            {
                return new BadRequestObjectResult(new { error = "invalid_request", error_description = "Token name is required." });
            }

            // Generate raw token
            var randomBytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            var rawToken = "atp_" + Convert.ToHexString(randomBytes).ToLower();

            // Compute hash
            string tokenHash;
            using (var sha256 = SHA256.Create())
            {
                var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawToken));
                tokenHash = Convert.ToHexString(hashedBytes).ToLower();
            }

            var pat = new PersonalAccessToken
            {
                UserId = userId,
                Name = body.Name,
                TokenHash = tokenHash,
                Scopes = body.Scopes,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = body.ExpiresInDays.HasValue ? DateTime.UtcNow.AddDays(body.ExpiresInDays.Value) : null
            };

            _dbContext.PersonalAccessTokens.Add(pat);
            await _dbContext.SaveChangesAsync();

            return new OkObjectResult(new
            {
                pat.Id,
                pat.Name,
                pat.Scopes,
                pat.CreatedAt,
                pat.ExpiresAt,
                RawToken = rawToken // Displayed only once!
            });
        }

        [Function("ListPats")]
        public async Task<IActionResult> ListPats(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "api/pat/list")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateToken(req, _tokenService, _logger);
            if (error != null) return error;

            var userId = principal!.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return new UnauthorizedObjectResult(new { error = "invalid_token_claims" });
            }

            var pats = await _dbContext.PersonalAccessTokens
                .Where(t => t.UserId == userId)
                .OrderByDescending(t => t.CreatedAt)
                .ToListAsync();

            var result = pats.Select(t => new
            {
                t.Id,
                t.Name,
                t.Scopes,
                t.CreatedAt,
                t.ExpiresAt,
                t.LastUsedAt
            });

            return new OkObjectResult(result);
        }

        [Function("DeletePat")]
        public async Task<IActionResult> DeletePat(
            [HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "api/pat/{id}")] HttpRequest req,
            string id)
        {
            var (principal, error) = AuthHelper.ValidateToken(req, _tokenService, _logger);
            if (error != null) return error;

            var userId = principal!.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return new UnauthorizedObjectResult(new { error = "invalid_token_claims" });
            }

            var pat = await _dbContext.PersonalAccessTokens
                .FirstOrDefaultAsync(t => t.Id == id && t.UserId == userId);

            if (pat == null)
            {
                return new NotFoundResult();
            }

            _dbContext.PersonalAccessTokens.Remove(pat);
            await _dbContext.SaveChangesAsync();

            return new OkResult();
        }
    }
}
