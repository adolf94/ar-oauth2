using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using backend.DTOs;
using backend.Services;
using System.Linq;

namespace backend.Endpoints
{
    public class AuthorizeFunction
    {
        private readonly ILogger<AuthorizeFunction> _logger;
        private readonly ClientService _clientService;

        public AuthorizeFunction(ILogger<AuthorizeFunction> logger, ClientService clientService)
        {
            _logger = logger;
            _clientService = clientService;
        }

        [Function("Authorize")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "authorize")] HttpRequest req)
        {
            _logger.LogInformation("Authorization endpoint invoked.");

            var request = new AuthorizeRequest
            {
                client_id             = (string?)req.Query["client_id"]             ?? string.Empty,
                redirect_uri          = (string?)req.Query["redirect_uri"]          ?? string.Empty,
                response_type         = (string?)req.Query["response_type"]         ?? string.Empty,
                state                 = (string?)req.Query["state"]                 ?? string.Empty,
                code_challenge        = (string?)req.Query["code_challenge"]        ?? string.Empty,
                code_challenge_method = (string?)req.Query["code_challenge_method"] ?? string.Empty,
                scope                 = (string?)req.Query["scope"]                 ?? string.Empty
            };

            // 1. Validate required parameters
            if (string.IsNullOrEmpty(request.client_id) || request.response_type != "code")
                return Error("invalid_request", "client_id and response_type=code are required.");

            // 2. Validate client_id and redirect_uri against the DB
            var client = await _clientService.GetByClientIdAsync(request.client_id);
            if (client == null)
                return Error("unauthorized_client", "Unknown client_id.");

            if (!string.IsNullOrEmpty(request.redirect_uri) &&
                !client.RedirectUris.Contains(request.redirect_uri))
                return Error("invalid_request", "redirect_uri is not registered for this client.");

            // 3. Redirect to the frontend login page, forwarding all PKCE params
            var loginUrl = $"http://localhost:5173/login" +
                           $"?client_id={Uri.EscapeDataString(request.client_id)}" +
                           $"&redirect_uri={Uri.EscapeDataString(request.redirect_uri)}" +
                           $"&state={Uri.EscapeDataString(request.state)}" +
                           $"&code_challenge={Uri.EscapeDataString(request.code_challenge)}" +
                           $"&code_challenge_method={Uri.EscapeDataString(request.code_challenge_method)}" +
                           $"&scope={Uri.EscapeDataString(request.scope)}";

            return new RedirectResult(loginUrl);
        }

        private static BadRequestObjectResult Error(string error, string description) =>
            new BadRequestObjectResult(new { error, error_description = description });
    }
}
