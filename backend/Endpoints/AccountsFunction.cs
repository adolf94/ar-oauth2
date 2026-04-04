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
        private readonly IUserService _userService;
        private readonly ITokenService _tokenService;

        public AccountsFunction(ILogger<AccountsFunction> logger, IUserService userService, ITokenService tokenService)
        {
            _logger = logger;
            _userService = userService;
            _tokenService = tokenService;
        }

        [Function("GetCurrentUser")]
        public async Task<IActionResult> GetCurrentUser(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "api/accounts/me")] HttpRequest req)
        {
            var userId = AuthHelper.GetSessionUserId(req, _tokenService);
            if (string.IsNullOrEmpty(userId))
                return new UnauthorizedObjectResult(new { error = "no_session" });

            var user = await _userService.GetByIdAsync(userId);
            if (user == null)
                return new UnauthorizedObjectResult(new { error = "user_not_found" });

            return new OkObjectResult(new
            {
                id = user.Id,
                email = user.Email,
                name = user.Name,
                picture = user.Picture
            });
        }
    }
}
