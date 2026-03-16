using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using backend.Models;
using backend.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace backend.Endpoints
{
    public class AdminClientEndpoints
    {
        private readonly ILogger<AdminClientEndpoints> _logger;
        private readonly ClientService _clientService;
        private readonly TokenService _tokenService;

        public AdminClientEndpoints(ILogger<AdminClientEndpoints> logger, ClientService clientService, TokenService tokenService)
        {
            _logger = logger;
            _clientService = clientService;
            _tokenService = tokenService;
        }

        [Function("GetClients")]
        public async Task<IActionResult> GetClients([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "manage/clients")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            _logger.LogInformation("Getting all registered clients.");
            var clients = await _clientService.GetAllClientsAsync();
            return new OkObjectResult(clients);
        }

        [Function("CreateClient")]
        public async Task<IActionResult> CreateClient([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "manage/clients")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            var data = JsonSerializer.Deserialize<Client>(requestBody, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (data == null || string.IsNullOrEmpty(data.ClientId))
                return new BadRequestObjectResult("Invalid client data.");

            var (newClient, plainSecret) = await _clientService.CreateClientAsync(data.ClientId, data.RedirectUris, data.AllowedScopes);
            
            // Return both the client object and the ONLY chance to see the plain secret
            return new OkObjectResult(new { client = newClient, plainSecret = plainSecret });
        }

        [Function("AddClientSecret")]
        public async Task<IActionResult> AddClientSecret([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "manage/clients/{id}/secrets")] HttpRequest req, string id)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            if (!Guid.TryParse(id, out Guid guidId)) return new BadRequestObjectResult("Invalid ID format");

            var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            var body = JsonSerializer.Deserialize<JsonElement>(requestBody);
            var description = body.TryGetProperty("description", out var desc) ? desc.GetString() : "New Secret";

            var plainSecret = await _clientService.AddSecretAsync(guidId, description ?? "New Secret");
            return new OkObjectResult(new { plainSecret = plainSecret });
        }
        
        [Function("UpdateClient")]
        public async Task<IActionResult> UpdateClient([HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = "manage/clients/{id}")] HttpRequest req, string id)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            if (!Guid.TryParse(id, out Guid guidId)) return new BadRequestObjectResult("Invalid ID format");

            var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            var data = JsonSerializer.Deserialize<Client>(requestBody, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (data == null) return new BadRequestObjectResult("Invalid client data.");

            var success = await _clientService.UpdateClientAsync(guidId, data.RedirectUris, data.AllowedScopes);
            if (!success) return new NotFoundResult();

            return new OkResult();
        }

        [Function("DeleteClient")]
        public async Task<IActionResult> DeleteClient([HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "manage/clients/{id}")] HttpRequest req, string id)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            if (!Guid.TryParse(id, out Guid guidId)) return new BadRequestObjectResult("Invalid ID format");
            
            var success = await _clientService.DeleteClientAsync(guidId);
            if (!success) return new NotFoundResult();

            return new OkResult();
        }

        [Function("DeleteClientSecret")]
        public async Task<IActionResult> DeleteClientSecret([HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "manage/clients/{id}/secrets/{secretId}")] HttpRequest req, string id, string secretId)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            if (!Guid.TryParse(id, out Guid guidId)) return new BadRequestObjectResult("Invalid ID format");

            var success = await _clientService.DeleteSecretAsync(guidId, secretId);
            if (!success) return new NotFoundResult();

            return new OkResult();
        }
    }
}
