using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using backend.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace backend.Endpoints
{
    public class LinkFunction
    {
        private readonly ILogger<LinkFunction> _logger;
        private readonly ITokenService _tokenService;
        private readonly IClientService _clientService;

        public LinkFunction(ILogger<LinkFunction> logger, ITokenService tokenService, IClientService clientService)
        {
            _logger = logger;
            _tokenService = tokenService;
            _clientService = clientService;
        }

        [Function("GetLinkToken")]
        public async Task<IActionResult> GetToken(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "api/accounts/link-token")] HttpRequest req)
        {
            _logger.LogInformation("Creating identity link token.");

            // 1. Authenticate Requestor via Bearer Token
            var authHeader = req.Headers["Authorization"].ToString();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                return new UnauthorizedObjectResult(new { error = "unauthorized" });

            var accessToken = authHeader.Substring(7);
            var principal = _tokenService.ValidateAccessToken(accessToken);
            if (principal == null)
                return new UnauthorizedObjectResult(new { error = "invalid_token" });

            // 2. Check for required scope: api://ar-auth-management/telegram:link:create
            var scopes = principal.FindFirst("scope")?.Value?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>();
            if (!scopes.Contains("api://ar-auth-management/telegram:link:create"))
            {
                _logger.LogWarning("Requestor {Sub} lacks required scope for linking.", principal.FindFirst(ClaimTypes.NameIdentifier)?.Value);
                return new ObjectResult(new { error = "insufficient_scope", scope = "api://ar-auth-management/telegram:link:create" }) { StatusCode = 403 };
            }

            var requestorId = principal.FindFirst("client_id")?.Value ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "unknown";

            // 3. Parse Request Body
            string requestBody;
            using (var reader = new StreamReader(req.Body))
                requestBody = await reader.ReadToEndAsync();

            var data = JsonSerializer.Deserialize<LinkTokenRequest>(requestBody, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (data == null || string.IsNullOrEmpty(data.TelegramId) || string.IsNullOrEmpty(data.ClientId))
                return new BadRequestObjectResult(new { error = "invalid_request", message = "telegram_id and client_id are required." });

            // 4. Validate Target Client
            var targetClient = await _clientService.GetByClientIdAsync(data.ClientId);
            if (targetClient == null)
                return new BadRequestObjectResult(new { error = "invalid_client", message = "Target client_id not found." });

            // 5. Generate Link Token
            var linkToken = _tokenService.GenerateLinkToken(data.TelegramId, data.ClientId, requestorId);

            return new OkObjectResult(new { link_token = linkToken });
        }

        public class LinkTokenRequest
        {
            public string TelegramId { get; set; } = string.Empty;
            public string ClientId { get; set; } = string.Empty;
        }
    }
}
