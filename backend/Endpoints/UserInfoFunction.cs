using System.Linq;
using System.Security.Claims;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using backend.Services;

namespace backend.Endpoints
{
    /// <summary>
    /// UserInfo endpoint — <c>GET /userinfo</c>.
    /// Validates the Bearer access token and returns the user's OIDC profile claims.
    /// </summary>
    public class UserInfoFunction
    {
        private readonly ILogger<UserInfoFunction> _logger;
        private readonly TokenService _tokenService;
        private readonly UserService _userService;

        public UserInfoFunction(
            ILogger<UserInfoFunction> logger,
            TokenService tokenService,
            UserService userService)
        {
            _logger = logger;
            _tokenService = tokenService;
            _userService = userService;
        }

        [Function("UserInfo")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = "api/userinfo")] HttpRequest req)
        {
            _logger.LogInformation("UserInfo endpoint invoked.");

            // Extract Bearer token from Authorization header
            var authHeader = req.Headers.Authorization.ToString();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                return new UnauthorizedObjectResult(new { error = "invalid_token", error_description = "Bearer token required." });

            var jwt = authHeader["Bearer ".Length..].Trim();

            // Validate token (audience is not enforced on the userinfo endpoint per spec)
            var principal = _tokenService.ValidateAccessToken(jwt);
            if (principal == null)
                return new UnauthorizedObjectResult(new { error = "invalid_token", error_description = "Token is invalid or expired." });

            var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
                      ?? principal.FindFirst("sub")?.Value;

            if (string.IsNullOrEmpty(userId))
                return new UnauthorizedObjectResult(new { error = "invalid_token" });

            var user = await _userService.GetByIdAsync(userId);
            if (user == null)
                return new NotFoundObjectResult(new { error = "not_found" });

            var response = new UserInfoResponse
            {
                Sub            = user.Id,
                Email          = user.Email,
                EmailVerified  = true,
                Roles          = user.Roles.ToArray()
            };

            return new OkObjectResult(response);
        }
    }

    public class UserInfoResponse
    {
        [JsonPropertyName("sub")]
        public string Sub { get; set; } = string.Empty;

        [JsonPropertyName("email")]
        public string Email { get; set; } = string.Empty;

        [JsonPropertyName("email_verified")]
        public bool EmailVerified { get; set; }

        [JsonPropertyName("roles")]
        public string[] Roles { get; set; } = System.Array.Empty<string>();
    }
}
