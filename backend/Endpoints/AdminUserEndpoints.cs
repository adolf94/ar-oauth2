using System;
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
    public class AdminUserEndpoints
    {
        private readonly ILogger<AdminUserEndpoints> _logger;
        private readonly UserService _userService;
        private readonly TokenService _tokenService;
        private readonly UserClientScopeService _userScopeService;

        public AdminUserEndpoints(
            ILogger<AdminUserEndpoints> logger, 
            UserService userService, 
            TokenService tokenService,
            UserClientScopeService userScopeService)
        {
            _logger = logger;
            _userService = userService;
            _tokenService = tokenService;
            _userScopeService = userScopeService;
        }

        [Function("GetUserClientScopes")]
        public async Task<IActionResult> GetUserClientScopes([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "api/manage/users/{userId}/scopes")] HttpRequest req, string userId)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            var scopes = await _userScopeService.GetUserScopesAsync(userId);
            return new OkObjectResult(scopes);
        }

        [Function("AssignUserClientScope")]
        public async Task<IActionResult> AssignUserClientScope([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "api/manage/users/{userId}/scopes")] HttpRequest req, string userId)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            var body = await new StreamReader(req.Body).ReadToEndAsync();
            var data = JsonSerializer.Deserialize<UserClientScope>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (data == null || string.IsNullOrEmpty(data.ClientId) || string.IsNullOrEmpty(data.Scope))
                return new BadRequestObjectResult("ClientId and Scope are required.");

            try
            {
                var mapping = await _userScopeService.AssignScopeAsync(userId, data.ClientId, data.Scope);
                return new OkObjectResult(mapping);
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult(ex.Message);
            }
        }

        [Function("RemoveUserClientScope")]
        public async Task<IActionResult> RemoveUserClientScope([HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "api/manage/users/scopes/{id}")] HttpRequest req, string id)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            if (!Guid.TryParse(id, out Guid guidId)) return new BadRequestObjectResult("Invalid ID format");

            var success = await _userScopeService.RemoveScopeAsync(guidId);
            if (!success) return new NotFoundResult();

            return new OkResult();
        }

        [Function("GetUsers")]
        public async Task<IActionResult> GetUsers([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "api/manage/users")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            _logger.LogInformation("Getting all registered users.");
            var users = await _userService.GetAllUsersAsync();
            return new OkObjectResult(users);
        }

        [Function("CreateUser")]
        public async Task<IActionResult> CreateUser([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "api/manage/users")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            var data = JsonSerializer.Deserialize<User>(requestBody, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (data == null || string.IsNullOrEmpty(data.Email))
                return new BadRequestObjectResult("Invalid user data.");
 
            var newUser = await _userService.CreateUserAsync(data.Email, data.MobileNumber, data.Roles);
            return new OkObjectResult(newUser);
        }
        
        [Function("UpdateUser")]
        public async Task<IActionResult> UpdateUser([HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = "api/manage/users/{id}")] HttpRequest req, string id)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            var data = JsonSerializer.Deserialize<User>(requestBody, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (data == null) return new BadRequestObjectResult("Invalid user data.");

            var success = await _userService.UpdateUserAsync(id, data.MobileNumber, data.Roles);
            if (!success) return new NotFoundResult();

            return new OkResult();
        }

        [Function("DeleteUser")]
        public async Task<IActionResult> DeleteUser([HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "api/manage/users/{id}")] HttpRequest req, string id)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            var success = await _userService.DeleteUserAsync(id);
            if (!success) return new NotFoundResult();

            return new OkResult();
        }
    }
}
