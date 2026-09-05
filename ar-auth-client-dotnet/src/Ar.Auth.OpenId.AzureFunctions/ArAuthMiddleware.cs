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
    private readonly string[] _anyScopes;
    private readonly HashSet<string> _excludedFunctions;

    /// <summary>
    /// Initializes a new instance of ArAuthMiddleware.
    /// </summary>
    public ArAuthMiddleware(
        IArAuthClient client,
        ArAuthOptions? options = null)
    {
        _client = client;
        _audience = options?.Audience;
        _requiredRoles = options?.RequiredRoles ?? Array.Empty<string>();
        _requiredScopes = options?.RequiredScopes ?? Array.Empty<string>();
        _anyScopes = options?.AnyScopes ?? Array.Empty<string>();
        _excludedFunctions = new HashSet<string>(options?.ExcludedFunctions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
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
            response.Headers.Add("WWW-Authenticate", "Bearer");
            await response.Body.WriteAsync(System.Text.Encoding.UTF8.GetBytes("Missing Authorization header."));
            context.GetInvocationResult().Value = response;
            return;
        }

        var authHeader = authValues.FirstOrDefault();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var response = httpRequestData.CreateResponse();
            response.StatusCode = HttpStatusCode.Unauthorized;
            response.Headers.Add("WWW-Authenticate", "Bearer error=\"invalid_request\", error_description=\"Invalid Authorization header format\"");
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
                        response.Headers.Add("WWW-Authenticate", "Bearer error=\"insufficient_scope\", error_description=\"Missing required role\"");
                        await response.Body.WriteAsync(System.Text.Encoding.UTF8.GetBytes($"Missing required role: {role}"));
                        context.GetInvocationResult().Value = response;
                        return;
                    }
                }
            }

            // Check required scopes
            var scopeClaim = principal.FindFirst("scope")?.Value ?? "";
            var userScopes = scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var scope in _requiredScopes)
            {
                if (!userScopes.Contains(scope))
                {
                    var response = httpRequestData.CreateResponse();
                    response.StatusCode = HttpStatusCode.Forbidden;
                    response.Headers.Add("WWW-Authenticate", $"Bearer error=\"insufficient_scope\", error_description=\"Missing required scope: {scope}\"");
                    await response.Body.WriteAsync(System.Text.Encoding.UTF8.GetBytes($"Missing required scope: {scope}"));
                    context.GetInvocationResult().Value = response;
                    return;
                }
            }

            // Check any-of scopes (at least one must be present)
            if (_anyScopes.Length > 0 && !_anyScopes.Any(userScopes.Contains))
            {
                var missing = string.Join(", ", _anyScopes);
                var response = httpRequestData.CreateResponse();
                response.StatusCode = HttpStatusCode.Forbidden;
                response.Headers.Add("WWW-Authenticate", $"Bearer error=\"insufficient_scope\", error_description=\"Missing required scope: any of {missing}\"");
                await response.Body.WriteAsync(System.Text.Encoding.UTF8.GetBytes($"Missing required scope: any of {missing}"));
                context.GetInvocationResult().Value = response;
                return;
            }

            // Store the principal in FunctionContext for downstream use
            context.Items["ArAuthUser"] = principal;
        }
        catch (Exceptions.TokenValidationException ex)
        {
            var response = httpRequestData.CreateResponse();
            response.StatusCode = HttpStatusCode.Unauthorized;
            response.Headers.Add("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"Token validation failed\"");
            await response.Body.WriteAsync(System.Text.Encoding.UTF8.GetBytes($"Token validation failed: {ex.Message}"));
            context.GetInvocationResult().Value = response;
            return;
        }

        await next(context);
    }
}
