using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using backend.Models;
using backend.Data;
using backend.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace backend.Endpoints
{
    public class AdminClientEndpoints
    {
        private readonly ILogger<AdminClientEndpoints> _logger;
        private readonly IClientService _clientService;
        private readonly ITokenService _tokenService;
        private readonly IApplicationScopeService _scopeService;
        private readonly IRoleDefinitionService _roleService;
        private readonly ICrossAppTrustService _trustService;
        private readonly AppDbContext _dbContext;

        public AdminClientEndpoints(
            ILogger<AdminClientEndpoints> logger, 
            IClientService clientService, 
            ITokenService tokenService,
            IApplicationScopeService scopeService,
            IRoleDefinitionService roleService,
            ICrossAppTrustService trustService,
            AppDbContext dbContext)
        {
            _logger = logger;
            _clientService = clientService;
            _tokenService = tokenService;
            _scopeService = scopeService;
            _roleService = roleService;
            _trustService = trustService;
            _dbContext = dbContext;
        }

        [Function("GetCrossAppTrusts")]
        public async Task<IActionResult> GetCrossAppTrusts([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "api/manage/trusts")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            var clientId = (string?)req.Query["client_id"];
            if (string.IsNullOrEmpty(clientId)) return new BadRequestObjectResult("client_id is required");

            var trusts = await _trustService.GetTrustsByRequestingClientAsync(clientId);
            return new OkObjectResult(trusts);
        }

        [Function("CreateCrossAppTrust")]
        public async Task<IActionResult> CreateCrossAppTrust([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "api/manage/trusts")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            var body = await new StreamReader(req.Body).ReadToEndAsync();
            var data = JsonSerializer.Deserialize<CrossAppTrust>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (data == null || string.IsNullOrEmpty(data.RequestingClientId) || string.IsNullOrEmpty(data.TargetClientId) || string.IsNullOrEmpty(data.ScopeName))
                return new BadRequestObjectResult("RequestingClientId, TargetClientId, and ScopeName are required.");

            try
            {
                var trust = await _trustService.CreateTrustAsync(data.RequestingClientId, data.TargetClientId, data.ScopeName);
                return new OkObjectResult(trust);
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult(ex.Message);
            }
        }

        [Function("DeleteCrossAppTrust")]
        public async Task<IActionResult> DeleteCrossAppTrust([HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "api/manage/trusts/{id}")] HttpRequest req, string id)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            var clientId = (string?)req.Query["client_id"];
            if (string.IsNullOrEmpty(clientId)) return new BadRequestObjectResult("client_id is required for partition key");

            if (!Guid.TryParse(id, out Guid guidId)) return new BadRequestObjectResult("Invalid ID format");

            var success = await _trustService.DeleteTrustAsync(guidId);
            if (!success) return new NotFoundResult();

            return new OkResult();
        }

        [Function("GetApplicationRoles")]
        public async Task<IActionResult> GetApplicationRoles([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "api/manage/roles")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            var clientId = (string?)req.Query["client_id"];
            if (string.IsNullOrEmpty(clientId)) return new BadRequestObjectResult("client_id is required");

            var roles = await _roleService.GetRolesByClientAsync(clientId);
            return new OkObjectResult(roles);
        }

        [Function("CreateApplicationRole")]
        public async Task<IActionResult> CreateApplicationRole([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "api/manage/roles")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            var body = await new StreamReader(req.Body).ReadToEndAsync();
            var data = JsonSerializer.Deserialize<RoleDefinition>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (data == null || string.IsNullOrEmpty(data.ClientId) || string.IsNullOrEmpty(data.Name))
                return new BadRequestObjectResult("ClientId and Name are required.");

            try
            {
                var role = await _roleService.CreateRoleAsync(data.ClientId, data.Name, data.Description);
                return new OkObjectResult(role);
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult(ex.Message);
            }
        }

        [Function("DeleteApplicationRole")]
        public async Task<IActionResult> DeleteApplicationRole([HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "api/manage/roles/{id}")] HttpRequest req, string id)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            var clientId = (string?)req.Query["client_id"];
            if (string.IsNullOrEmpty(clientId)) return new BadRequestObjectResult("client_id is required for partition key");

            if (!Guid.TryParse(id, out Guid guidId)) return new BadRequestObjectResult("Invalid ID format");

            var success = await _roleService.DeleteRoleAsync(guidId);
            if (!success) return new NotFoundResult();

            return new OkResult();
        }

        [Function("GetApplicationScopes")]
        public async Task<IActionResult> GetApplicationScopes([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "api/manage/scopes")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            var clientId = (string?)req.Query["client_id"];
            if (!string.IsNullOrEmpty(clientId))
            {
                var scopes = await _scopeService.GetScopesByClientAsync(clientId);
                return new OkObjectResult(scopes);
            }
            else
            {
                var scopes = await _scopeService.GetAllScopesAsync();
                return new OkObjectResult(scopes);
            }
        }

        [Function("CreateApplicationScope")]
        public async Task<IActionResult> CreateApplicationScope([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "api/manage/scopes")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            var body = await new StreamReader(req.Body).ReadToEndAsync();
            var data = JsonSerializer.Deserialize<ApplicationScope>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (data == null || string.IsNullOrEmpty(data.ClientId) || string.IsNullOrEmpty(data.Name))
                return new BadRequestObjectResult("ClientId and Name are required.");

            try
            {
                var scope = await _scopeService.CreateScopeAsync(data.ClientId, data.Name, data.Description, data.IsAdminApproved == true, data.IsClientOnly == true);
                return new OkObjectResult(scope);
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult(ex.Message);
            }
        }

        [Function("DeleteApplicationScope")]
        public async Task<IActionResult> DeleteApplicationScope([HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "api/manage/scopes/{id}")] HttpRequest req, string id)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            if (!Guid.TryParse(id, out Guid guidId)) return new BadRequestObjectResult("Invalid ID format");

            var success = await _scopeService.DeleteScopeAsync(guidId);
            if (!success) return new NotFoundResult();

            return new OkResult();
        }

        public class ClientSummaryDto : Client
        {
            public int RoleCount { get; set; }
            public int ScopeCount { get; set; }
            public int AutoGrantCount { get; set; }
            public int ClientOnlyCount { get; set; }
            public int TrustCount { get; set; }
        }

        [Function("GetClients")]
        public async Task<IActionResult> GetClients([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "api/manage/clients")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            _logger.LogInformation("Getting all registered clients with metadata.");
            var clients = await _clientService.GetAllClientsAsync();
            
            // Fetch all metadata in parallel for efficiency
            var allRoles = await _dbContext.RoleDefinitions.ToListAsync();
            var allScopes = await _dbContext.ApplicationScopes.ToListAsync();
            var allTrusts = await _dbContext.CrossAppTrusts.ToListAsync();

            var summarizedClients = clients.Select(c => new ClientSummaryDto
            {
                Id = c.Id,
                ClientId = c.ClientId,
                RedirectUris = c.RedirectUris,
                AllowedScopes = c.AllowedScopes,
                ClientSecrets = c.ClientSecrets,
                TelegramBotClientId = c.TelegramBotClientId,
                RoleCount = allRoles.Count(r => r.ClientId == c.ClientId),
                ScopeCount = allScopes.Count(s => s.ClientId == c.ClientId),
                AutoGrantCount = allScopes.Count(s => s.ClientId == c.ClientId && s.IsAdminApproved == true),
                ClientOnlyCount = allScopes.Count(s => s.ClientId == c.ClientId && s.IsClientOnly == true),
                TrustCount = allTrusts.Count(t => t.RequestingClientId == c.ClientId)
            }).ToList();

            return new OkObjectResult(summarizedClients);
        }

        public class ClientCreationRequest : Client
        {
            public bool IsPublic { get; set; }
            // Re-declare for deserialization since base is JsonIgnored
            public new string? TelegramBotClientSecret { get; set; }
        }

        public class ClientUpdateRequest : Client
        {
            // Re-declare for deserialization since base is JsonIgnored
            public new string? TelegramBotClientSecret { get; set; }
        }

        [Function("CreateClient")]
        public async Task<IActionResult> CreateClient([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "api/manage/clients")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            var data = JsonSerializer.Deserialize<ClientCreationRequest>(requestBody, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (data == null || string.IsNullOrEmpty(data.ClientId))
                return new BadRequestObjectResult("Invalid client data.");

            if (data.IsPublic)
            {
                var newClient = await _clientService.CreatePublicClientAsync(data.ClientId, data.RedirectUris, data.AllowedScopes, data.TelegramBotClientId, data.TelegramBotClientSecret);
                return new OkObjectResult(new { client = newClient, plainSecret = (string?)null });
            }
            else
            {
                var (newClient, plainSecret) = await _clientService.CreateClientAsync(data.ClientId, data.RedirectUris, data.AllowedScopes, data.TelegramBotClientId, data.TelegramBotClientSecret);
                return new OkObjectResult(new { client = newClient, plainSecret = plainSecret });
            }
        }

        [Function("AddClientSecret")]
        public async Task<IActionResult> AddClientSecret([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "api/manage/clients/{id}/secrets")] HttpRequest req, string id)
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
        public async Task<IActionResult> UpdateClient([HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = "api/manage/clients/{id}")] HttpRequest req, string id)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            if (!Guid.TryParse(id, out Guid guidId)) return new BadRequestObjectResult("Invalid ID format");

            var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            var data = JsonSerializer.Deserialize<ClientUpdateRequest>(requestBody, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (data == null) return new BadRequestObjectResult("Invalid client data.");

            var success = await _clientService.UpdateClientAsync(guidId, data.RedirectUris, data.AllowedScopes, data.TelegramBotClientId, data.TelegramBotClientSecret);
            if (!success) return new NotFoundResult();

            return new OkResult();
        }

        [Function("DeleteClient")]
        public async Task<IActionResult> DeleteClient([HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "api/manage/clients/{id}")] HttpRequest req, string id)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            if (!Guid.TryParse(id, out Guid guidId)) return new BadRequestObjectResult("Invalid ID format");
            
            var success = await _clientService.DeleteClientAsync(guidId);
            if (!success) return new NotFoundResult();

            return new OkResult();
        }

        [Function("DeleteClientSecret")]
        public async Task<IActionResult> DeleteClientSecret([HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "api/manage/clients/{id}/secrets/{secretId}")] HttpRequest req, string id, string secretId)
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
