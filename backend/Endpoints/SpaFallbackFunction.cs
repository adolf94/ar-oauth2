using System.Net;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;
using System.IO;
using System.Threading.Tasks;

namespace backend.Endpoints
{
    public class SpaFallbackFunction
    {
        private readonly ILogger<SpaFallbackFunction> _logger;
        private readonly IHostEnvironment _env;

        public SpaFallbackFunction(ILogger<SpaFallbackFunction> logger, IHostEnvironment env)
        {
            _logger = logger;
            _env = env;
        }

        [Function("SpaFallback")]
        public async Task<HttpResponseData> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "{*path}")] HttpRequestData req,
            string? path)
        {
            // Do not intercept API requests or well-known endpoints
            if (path != null && (path.StartsWith("api/") || path.StartsWith(".well-known/")))
            {
                return req.CreateResponse(HttpStatusCode.NotFound);
            }

            var safePath = string.IsNullOrEmpty(path) ? "index.html" : path.Replace("/", Path.DirectorySeparatorChar.ToString());
            var filePath = Path.Combine(_env.ContentRootPath, "wwwroot", safePath);

            // If an explicit file matches, serve it
            if (File.Exists(filePath))
            {
                return await ServeFileAsync(req, filePath);
            }

            // Otherwise, serve the SPA index.html
            var indexPath = Path.Combine(_env.ContentRootPath, "wwwroot", "index.html");
            if (File.Exists(indexPath))
            {
                return await ServeFileAsync(req, indexPath, "text/html; charset=utf-8");
            }

            var notFoundResponse = req.CreateResponse(HttpStatusCode.NotFound);
            await notFoundResponse.WriteStringAsync("Not Found");
            return notFoundResponse;
        }

        private async Task<HttpResponseData> ServeFileAsync(HttpRequestData req, string filePath, string? overrideContentType = null)
        {
            var response = req.CreateResponse(HttpStatusCode.OK);
            string contentType = overrideContentType ?? GetContentType(filePath);
            
            response.Headers.Add("Content-Type", contentType);
            var bytes = await File.ReadAllBytesAsync(filePath);
            await response.Body.WriteAsync(bytes, 0, bytes.Length);
            return response;
        }

        private string GetContentType(string filePath)
        {
            var extension = Path.GetExtension(filePath).ToLower();
            return extension switch
            {
                ".html" => "text/html; charset=utf-8",
                ".js" => "application/javascript",
                ".css" => "text/css",
                ".png" => "image/png",
                ".jpg" => "image/jpeg",
                ".svg" => "image/svg+xml",
                ".ico" => "image/x-icon",
                ".json" => "application/json",
                _ => "application/octet-stream"
            };
        }
    }
}
