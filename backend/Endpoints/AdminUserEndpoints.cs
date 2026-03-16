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

        public AdminUserEndpoints(ILogger<AdminUserEndpoints> logger, UserService userService, TokenService tokenService)
        {
            _logger = logger;
            _userService = userService;
            _tokenService = tokenService;
        }

        [Function("GetUsers")]
        public async Task<IActionResult> GetUsers([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "manage/users")] HttpRequest req)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            _logger.LogInformation("Getting all registered users.");
            var users = await _userService.GetAllUsersAsync();
            return new OkObjectResult(users);
        }

        [Function("CreateUser")]
        public async Task<IActionResult> CreateUser([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "manage/users")] HttpRequest req)
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
        public async Task<IActionResult> UpdateUser([HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = "manage/users/{id}")] HttpRequest req, string id)
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
        public async Task<IActionResult> DeleteUser([HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "manage/users/{id}")] HttpRequest req, string id)
        {
            var (principal, error) = AuthHelper.ValidateAdmin(req, _tokenService, _logger);
            if (error != null) return error;

            var success = await _userService.DeleteUserAsync(id);
            if (!success) return new NotFoundResult();

            return new OkResult();
        }
    }
}
