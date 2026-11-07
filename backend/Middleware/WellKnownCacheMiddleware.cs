using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Middleware;

namespace backend.Middleware
{
    /// <summary>
    /// Adds Cache-Control headers to the OIDC discovery documents so that Cloudflare
    /// (in front of the Functions app) can serve them from the edge instead of
    /// hitting the function app — this removes cold-start latency for discovery
    /// and JWKS requests.
    ///
    /// Both documents are effectively static (signing keys are long-lived), so a
    /// 24h TTL is safe. If keys ever rotate, purge the Cloudflare cache to
    /// propagate immediately.
    /// </summary>
    public class WellKnownCacheMiddleware : IFunctionsWorkerMiddleware
    {
        public async Task Invoke(FunctionContext context, FunctionExecutionDelegate next)
        {
            var httpContext = context.GetHttpContext();

            if (httpContext?.Request.Path.Value?.Contains("/.well-known/", StringComparison.OrdinalIgnoreCase) == true)
            {
                httpContext.Response.Headers.CacheControl = "public, max-age=86400"; // 24 hours
            }

            await next(context);
        }
    }
}
