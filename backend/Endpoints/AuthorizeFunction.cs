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
        private readonly IClientService _clientService;
        private readonly IAuthCodeService _authCodeService;
        private readonly ITokenService _tokenService;

        public AuthorizeFunction(
            ILogger<AuthorizeFunction> logger, 
            IClientService clientService,
            IAuthCodeService authCodeService,
            ITokenService tokenService)
        {
            _logger = logger;
            _clientService = clientService;
            _authCodeService = authCodeService;
            _tokenService = tokenService;
        }

        [Function("Authorize")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "api/authorize")] HttpRequest req)
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
                scope                 = (string?)req.Query["scope"]                 ?? string.Empty,
                link_token            = (string?)req.Query["link_token"]
            };

            // 1. Validate required parameters
            if (string.IsNullOrEmpty(request.client_id) || request.response_type != "code")
                return RedirectToError("invalid_request", "client_id and response_type=code are required.");

            // 2. Validate client_id and redirect_uri against the DB
            var client = await _clientService.GetByClientIdAsync(request.client_id);
            if (client == null)
                return RedirectToError("unauthorized_client", "Unknown client_id.");

            if (!string.IsNullOrEmpty(request.redirect_uri) &&
                !client.RedirectUris.Contains(request.redirect_uri))
                return RedirectToError("invalid_request", "redirect_uri is not registered for this client.");

            // 3. Enforce PKCE for public clients
            if ((client.ClientSecrets == null || !client.ClientSecrets.Any()) && string.IsNullOrEmpty(request.code_challenge))
                return RedirectToError("invalid_request", "PKCE (code_challenge) is required for public clients.");

            // 4. Check for existing session (Auto-Login)
            // We only bypass the login page if explicitly requested via skip_prompt=true
            // Otherwise, we let the SPA show the "Active Session" UI first.
            var skipPrompt = (string?)req.Query["skip_prompt"] == "true";
            if (skipPrompt)
            {
                var sessionUserId = AuthHelper.GetSessionUserId(req, _tokenService);
                if (!string.IsNullOrEmpty(sessionUserId))
                {
                    _logger.LogInformation("Bypassing login via skip_prompt=true for user {UserId}.", sessionUserId);
                    
                    var authCode = await _authCodeService.CreateAuthCodeAsync(
                        request.client_id,
                        sessionUserId,
                        request.redirect_uri,
                        request.code_challenge,
                        request.code_challenge_method,
                        request.scope
                    );

                    var successUrl = request.redirect_uri;
                    successUrl += (successUrl.Contains("?") ? "&" : "?") + $"code={System.Uri.EscapeDataString(authCode.Id)}";
                    if (!string.IsNullOrEmpty(request.state))
                        successUrl += $"&state={System.Uri.EscapeDataString(request.state)}";

                    return new RedirectResult(successUrl);
                }
            }

            // 5. Redirect to the local SPA login page, forwarding all PKCE params
            var loginUrl = $"/login" +
                           $"?client_id={Uri.EscapeDataString(request.client_id)}" +
                           $"&response_type={Uri.EscapeDataString(request.response_type)}" +
                           $"&redirect_uri={Uri.EscapeDataString(request.redirect_uri)}" +
                           $"&state={Uri.EscapeDataString(request.state)}" +
                           $"&code_challenge={Uri.EscapeDataString(request.code_challenge)}" +
                           $"&code_challenge_method={Uri.EscapeDataString(request.code_challenge_method)}" +
                           $"&scope={Uri.EscapeDataString(request.scope)}" +
                           (string.IsNullOrEmpty(request.link_token) ? "" : $"&link_token={Uri.EscapeDataString(request.link_token)}");

            return new RedirectResult(loginUrl);
        }

        private static RedirectResult RedirectToError(string error, string description) =>
            new RedirectResult($"/error?error={Uri.EscapeDataString(error)}&error_description={Uri.EscapeDataString(description)}");
    }
}
