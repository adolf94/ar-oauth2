using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using backend.Models;
using backend.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace backend.Endpoints
{
    public class AccountsFunction
    {
        private readonly ILogger<AccountsFunction> _logger;
        private readonly UserService _userService;
        private readonly TokenService _tokenService;

        public AccountsFunction(ILogger<AccountsFunction> logger, UserService userService, TokenService tokenService)
        {
            _logger = logger;
            _userService = userService;
            _tokenService = tokenService;
        }

        [Function("GetRecentAccounts")]
        public async Task<IActionResult> GetRecentAccounts(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "api/accounts/recent")] HttpRequest req)
        {
            var userIds = AuthHelper.GetRecentUserIds(req);
            if (userIds.Count == 0) return new OkObjectResult(new List<object>());

            var result = new List<object>();
            foreach (var id in userIds)
            {
                var user = await _userService.GetByIdAsync(id);
                if (user != null)
                {
                    result.Add(new { 
                        id = user.Id, 
                        email = user.Email,
                        provider = "unknown" // We don't store provider in cookie, but it's enough for UX
                    });
                }
            }

            return new OkObjectResult(result);
        }

        [Function("RemoveRecentAccount")]
        public IActionResult RemoveRecentAccount(
            [HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "api/accounts/recent/{userId}")] HttpRequest req, string userId)
        {
            var userIds = AuthHelper.GetRecentUserIds(req);
            if (userIds.Contains(userId))
            {
                userIds.Remove(userId);
                AuthHelper.SetRecentUserIds(req.HttpContext.Response, userIds);
            }
            return new OkResult();
        }
    }
}
