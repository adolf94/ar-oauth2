using System;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace backend.Endpoints
{
    /// <summary>
    /// JWKS endpoint — <c>GET /.well-known/jwks.json</c>.
    /// HS256 is symmetric so we can't expose a public key; we return an empty key set.
    /// When RS256 is adopted, this endpoint will return the RSA public key.
    /// </summary>
    public class JwksFunction
    {
        private readonly ILogger<JwksFunction> _logger;
        private readonly Services.RsaKeyService _rsaKeyService;

        public JwksFunction(ILogger<JwksFunction> logger, Services.RsaKeyService rsaKeyService)
        {
            _logger = logger;
            _rsaKeyService = rsaKeyService;
        }

        [Function("Jwks")]
        public IActionResult Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get",
                Route = ".well-known/jwks.json")] HttpRequest req)
        {
            _logger.LogInformation("JWKS endpoint invoked.");

            var jwks = new
            {
                keys = _rsaKeyService.GetAllKeys().Select(k =>
                {
                    var parameters = k.Rsa.ExportParameters(false);
                    return new
                    {
                        kty = "RSA",
                        use = "sig",
                        kid = k.KeyId,
                        alg = "RS256",
                        n = Convert.ToBase64String(parameters.Modulus!).Replace('+', '-').Replace('/', '_').TrimEnd('='),
                        e = Convert.ToBase64String(parameters.Exponent!).Replace('+', '-').Replace('/', '_').TrimEnd('=')
                    };
                }).ToArray()
            };

            return new OkObjectResult(jwks);
        }
    }
}
