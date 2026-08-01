using System.Net;
using System.Security.Claims;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Azure.Functions.Worker.Middleware;

namespace Ar.Auth.OpenId.AzureFunctions;

/// <summary>
/// Azure Functions Isolated Worker middleware that validates JWT Bearer tokens
/// on HTTP-triggered functions. The decoded ClaimsPrincipal is stored in FunctionContext.Items
/// under the key "ArAuthUser".
/// </summary>
public class ArAuthMiddleware : IFunctionsWorkerMiddleware
{
    private readonly IArAuthClient _client;
    private readonly string? _audience;
    private readonly string[] _requiredRoles;
    private readonly string[] _requiredScopes;
    private readonly HashSet<string> _excludedFunctions;

    /// <summary>
    /// Initializes a new instance of ArAuthMiddleware.
    /// </summary>
    public ArAuthMiddleware(
        IArAuthClient client,
        ArAuthMiddlewareOptions? middlewareOptions = null)
    {
        _client = client;
        _audience = middlewareOptions?.Audience;
        _requiredRoles = middlewareOptions?.RequiredRoles ?? Array.Empty<string>();
        _requiredScopes = middlewareOptions?.RequiredScopes ?? Array.Empty<string>();
        _excludedFunctions = new HashSet<string>(middlewareOptions?.ExcludedFunctions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
    }

    /// <inheritdoc />
    public async Task Invoke(FunctionContext context, FunctionExecutionDelegate next)
    {
        // Check if the function is excluded from authentication
        if (_excludedFunctions.Contains(context.FunctionDefinition.Name))
        {
            await next(context);
            return;
        }

        // Only process HTTP triggers
        var httpRequestData = await context.GetHttpRequestDataAsync();
        if (httpRequestData == null)
        {
            await next(context);
            return;
        }

        // Extract Authorization header
        if (!httpRequestData.Headers.TryGetValues("Authorization", out var authValues))
        {
            var response = httpRequestData.CreateResponse();
            response.StatusCode = HttpStatusCode.Unauthorized;
            await response.Body.WriteAsync(System.Text.Encoding.UTF8.GetBytes("Missing Authorization header."));
            context.GetInvocationResult().Value = response;
            return;
        }

        var authHeader = authValues.FirstOrDefault();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var response = httpRequestData.CreateResponse();
            response.StatusCode = HttpStatusCode.Unauthorized;
            await response.Body.WriteAsync(System.Text.Encoding.UTF8.GetBytes("Invalid Authorization header format. Expected: Bearer <token>."));
            context.GetInvocationResult().Value = response;
            return;
        }

        var token = authHeader.Substring("Bearer ".Length).Trim();

        try
        {
            var principal = await _client.VerifyTokenAsync(token, _audience);

            // Check required roles
            if (_requiredRoles.Length > 0)
            {
                var userRoles = principal.FindAll(c => c.Type == ClaimTypes.Role || c.Type == "roles")
                    .Select(c => c.Value)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                foreach (var role in _requiredRoles)
                {
                    if (!userRoles.Contains(role))
                    {
                        var response = httpRequestData.CreateResponse();
                        response.StatusCode = HttpStatusCode.Forbidden;
                        await response.Body.WriteAsync(System.Text.Encoding.UTF8.GetBytes($"Missing required role: {role}"));
                        context.GetInvocationResult().Value = response;
                        return;
                    }
                }
            }

            // Check required scopes
            if (_requiredScopes.Length > 0)
            {
                var scopeClaim = principal.FindFirst("scope")?.Value ?? "";
                var userScopes = scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                foreach (var scope in _requiredScopes)
                {
                    if (!userScopes.Contains(scope))
                    {
                        var response = httpRequestData.CreateResponse();
                        response.StatusCode = HttpStatusCode.Forbidden;
                        await response.Body.WriteAsync(System.Text.Encoding.UTF8.GetBytes($"Missing required scope: {scope}"));
                        context.GetInvocationResult().Value = response;
                        return;
                    }
                }
            }

            // Store the principal in FunctionContext for downstream use
            context.Items["ArAuthUser"] = principal;
        }
        catch (Exceptions.TokenValidationException ex)
        {
            var response = httpRequestData.CreateResponse();
            response.StatusCode = HttpStatusCode.Unauthorized;
            await response.Body.WriteAsync(System.Text.Encoding.UTF8.GetBytes($"Token validation failed: {ex.Message}"));
            context.GetInvocationResult().Value = response;
            return;
        }

        await next(context);
    }
}

/// <summary>
/// Options for configuring the ArAuth Azure Functions middleware.
/// </summary>
public class ArAuthMiddlewareOptions
{
    /// <summary>Expected audience (aud) claim. Optional.</summary>
    public string? Audience { get; set; }

    /// <summary>Roles required to access the function. Optional.</summary>
    public string[]? RequiredRoles { get; set; }

    /// <summary>Scopes required to access the function. Optional.</summary>
    public string[]? RequiredScopes { get; set; }

    /// <summary>A list of function names that should bypass authentication. Optional.</summary>
    public string[]? ExcludedFunctions { get; set; }
}
