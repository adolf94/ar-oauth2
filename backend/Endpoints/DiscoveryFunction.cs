using System;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace backend.Endpoints
{
    /// <summary>
    /// OIDC Discovery Document — <c>GET /.well-known/openid-configuration</c>.
    /// Returns the standard metadata that OIDC clients use to auto-configure.
    /// Route is mapped as <c>api/.well-known/openid-configuration</c> by the Functions runtime.
    /// </summary>
    public class DiscoveryFunction
    {
        private readonly ILogger<DiscoveryFunction> _logger;
        private readonly Configuration.AppConfig _appConfig;

        public DiscoveryFunction(ILogger<DiscoveryFunction> logger, Configuration.AppConfig appConfig)
        {
            _logger = logger;
            _appConfig = appConfig;
        }

        [Function("OpenIdConfiguration")]
        public IActionResult Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get",
                Route = "api/.well-known/openid-configuration")] HttpRequest req)
        {
            _logger.LogInformation("OpenID configuration endpoint invoked.");

            var issuer = _appConfig.Jwt.Issuer;

            var doc = new OidcDiscoveryDocument
            {
                Issuer                            = issuer,
                AuthorizationEndpoint             = $"{issuer}/authorize",
                TokenEndpoint                     = $"{issuer}/token",
                UserInfoEndpoint                  = $"{issuer}/userinfo",
                JwksUri                           = $"{issuer}/.well-known/jwks.json",
                ResponseTypesSupported            = new[] { "code" },
                SubjectTypesSupported             = new[] { "public" },
                IdTokenSigningAlgValuesSupported   = new[] { "RS256" },
                ScopesSupported                   = new[] { "openid", "profile", "email" },
                TokenEndpointAuthMethodsSupported  = new[] { "none" },    // PKCE-only, no client_secret
                GrantTypesSupported               = new[] { "authorization_code", "refresh_token" },
                ClaimsSupported                   = new[] { "sub", "email", "roles", "scope", "client_id" }
            };

            return new OkObjectResult(doc);
        }
    }

    public class OidcDiscoveryDocument
    {
        [JsonPropertyName("issuer")]
        public string Issuer { get; set; } = string.Empty;

        [JsonPropertyName("authorization_endpoint")]
        public string AuthorizationEndpoint { get; set; } = string.Empty;

        [JsonPropertyName("token_endpoint")]
        public string TokenEndpoint { get; set; } = string.Empty;

        [JsonPropertyName("userinfo_endpoint")]
        public string UserInfoEndpoint { get; set; } = string.Empty;

        [JsonPropertyName("jwks_uri")]
        public string JwksUri { get; set; } = string.Empty;

        [JsonPropertyName("response_types_supported")]
        public string[] ResponseTypesSupported { get; set; } = Array.Empty<string>();

        [JsonPropertyName("subject_types_supported")]
        public string[] SubjectTypesSupported { get; set; } = Array.Empty<string>();

        [JsonPropertyName("id_token_signing_alg_values_supported")]
        public string[] IdTokenSigningAlgValuesSupported { get; set; } = Array.Empty<string>();

        [JsonPropertyName("scopes_supported")]
        public string[] ScopesSupported { get; set; } = Array.Empty<string>();

        [JsonPropertyName("token_endpoint_auth_methods_supported")]
        public string[] TokenEndpointAuthMethodsSupported { get; set; } = Array.Empty<string>();

        [JsonPropertyName("grant_types_supported")]
        public string[] GrantTypesSupported { get; set; } = Array.Empty<string>();

        [JsonPropertyName("claims_supported")]
        public string[] ClaimsSupported { get; set; } = Array.Empty<string>();
    }
}
