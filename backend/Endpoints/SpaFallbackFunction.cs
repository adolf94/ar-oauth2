using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;
using System.IO;
using System.Threading.Tasks;
using System;
using System.Net;

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

        [Function("Z_SpaFallback")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "{*path}")] HttpRequest req,
            string? path)
        {
            // Do not intercept API requests or well-known endpoints
            if (path != null && path.StartsWith("api/"))
            {
                return new NotFoundResult();
            }

            var baseDir = AppContext.BaseDirectory;
            var safePath = string.IsNullOrEmpty(path) ? "index.html" : path.Replace("/", Path.DirectorySeparatorChar.ToString());
            var filePath = Path.Combine(baseDir, "wwwroot", safePath);

            // If an explicit file matches, serve it
            if (File.Exists(filePath))
            {
                return await ServeFileAsync(filePath);
            }

            // Otherwise, serve the SPA index.html
            var indexPath = Path.Combine(baseDir, "wwwroot", "index.html");
            if (File.Exists(indexPath))
            {
                return await ServeFileAsync(indexPath, "text/html; charset=utf-8");
            }

            _logger.LogInformation($"File was not found in {filePath}");
            return new NotFoundResult();
        }

        private async Task<IActionResult> ServeFileAsync(string filePath, string? overrideContentType = null)
        {
            string contentType = overrideContentType ?? GetContentType(filePath);
            var bytes = await File.ReadAllBytesAsync(filePath);
            return new FileContentResult(bytes, contentType);
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
