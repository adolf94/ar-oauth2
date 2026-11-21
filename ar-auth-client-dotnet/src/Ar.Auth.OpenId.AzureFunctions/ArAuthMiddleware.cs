using System.Net;
using System.Security.Claims;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Azure.Functions.Worker.Middleware;

namespace Ar.Auth.OpenId.AzureFunctions;

/// <summary>
/// Azure Functions Isolated Worker middleware that validates credentials on HTTP-triggered
/// functions. The decoded ClaimsPrincipal is stored in FunctionContext.Items under the key
/// "ArAuthUser".
///
/// Credential resolution: an explicit Authorization: Bearer header always wins. When no
/// header is present and <see cref="ArAuthOptions.AllowSessionCookie"/> is enabled, the
/// auth server's session cookie (see <see cref="ArAuthOptions.CookieName"/>) is accepted
/// as a fallback credential — subject to a CSRF origin guard. This is only useful when the
/// API shares a registrable domain (site) with the auth server; browsers never send the
/// auth server's cookie to an API on a different domain.
///
/// Session principals carry sub/email/name only — no roles or scopes — so configured
/// RequiredRoles/RequiredScopes still fail cleanly for cookie-authenticated callers.
/// </summary>
public class ArAuthMiddleware : IFunctionsWorkerMiddleware
{
    private readonly IArAuthClient _client;
    private readonly ArAuthOptions? _options;
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
        _options = options;
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

        // ── Credential resolution: explicit Bearer header wins over the session cookie ──

        ClaimsPrincipal? principal = null;

        if (httpRequestData.Headers.TryGetValues("Authorization", out var authValues))
        {
            var authHeader = authValues.FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                await WriteErrorAndStopAsync(context, httpRequestData, HttpStatusCode.Unauthorized,
                    "Bearer error=\"invalid_request\", error_description=\"Invalid Authorization header format\"",
                    "Invalid Authorization header format. Expected: Bearer <token>.");
                return;
            }

            var token = authHeader.Substring("Bearer ".Length).Trim();

            try
            {
                principal = await _client.VerifyTokenAsync(token, _audience);
            }
            catch (Exceptions.TokenValidationException ex)
            {
                await WriteErrorAndStopAsync(context, httpRequestData, HttpStatusCode.Unauthorized,
                    "Bearer error=\"invalid_token\", error_description=\"Token validation failed\"",
                    $"Token validation failed: {ex.Message}");
                return;
            }
        }
        else if (_options is { AllowSessionCookie: true })
        {
            principal = await TryAuthenticateViaSessionCookieAsync(httpRequestData);
            if (principal == null)
            {
                await WriteErrorAndStopAsync(context, httpRequestData, HttpStatusCode.Unauthorized,
                    "Bearer",
                    "Missing Authorization header and no valid session cookie.");
                return;
            }
        }

        if (principal == null)
        {
            await WriteErrorAndStopAsync(context, httpRequestData, HttpStatusCode.Unauthorized,
                "Bearer",
                "Missing Authorization header.");
            return;
        }

        // ── Shared role/scope requirements (applied to both credential paths) ──

        var errorResponse = CheckRequirements(httpRequestData, principal);
        if (errorResponse != null)
        {
            context.GetInvocationResult().Value = errorResponse;
            return;
        }

        // Store the principal in FunctionContext for downstream use
        context.Items["ArAuthUser"] = principal;

        await next(context);
    }

    private async Task<ClaimsPrincipal?> TryAuthenticateViaSessionCookieAsync(HttpRequestData httpRequestData)
    {
        var cookieToken = GetCookieValue(httpRequestData, _options!.CookieName);
        if (string.IsNullOrEmpty(cookieToken))
        {
            return null;
        }

        // CSRF guard: only honor the cookie for same-origin (or allow-listed) callers.
        // Origin is absent on same-site GET navigations but always present on unsafe
        // methods from browsers, so absence on unsafe methods is rejected.
        if (!SessionCookieGuard.IsOriginAllowed(
                httpRequestData.Method,
                GetHeaderValue(httpRequestData, "Origin"),
                GetHeaderValue(httpRequestData, "Referer"),
                httpRequestData.Url.GetLeftPart(UriPartial.Authority),
                _options.AllowedCookieOrigins))
        {
            return null;
        }

        try
        {
            return await _client.ValidateSessionTokenAsync(cookieToken);
        }
        catch (Exceptions.TokenValidationException)
        {
            // Invalid/expired session cookie → treated as unauthenticated.
            return null;
        }
    }

    private HttpResponseData? CheckRequirements(HttpRequestData httpRequestData, ClaimsPrincipal principal)
    {
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
                    return CreateErrorResponse(httpRequestData, HttpStatusCode.Forbidden,
                        "Bearer error=\"insufficient_scope\", error_description=\"Missing required role\"",
                        $"Missing required role: {role}");
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
                return CreateErrorResponse(httpRequestData, HttpStatusCode.Forbidden,
                    $"Bearer error=\"insufficient_scope\", error_description=\"Missing required scope: {scope}\"",
                    $"Missing required scope: {scope}");
            }
        }

        // Check any-of scopes (at least one must be present)
        if (_anyScopes.Length > 0 && !_anyScopes.Any(userScopes.Contains))
        {
            var missing = string.Join(", ", _anyScopes);
            return CreateErrorResponse(httpRequestData, HttpStatusCode.Forbidden,
                $"Bearer error=\"insufficient_scope\", error_description=\"Missing required scope: any of {missing}\"",
                $"Missing required scope: any of {missing}");
        }

        return null;
    }

    private static string? GetCookieValue(HttpRequestData httpRequestData, string name)
    {
        return httpRequestData.Cookies.FirstOrDefault(c =>
            string.Equals(c.Name, name, StringComparison.OrdinalIgnoreCase))?.Value;
    }

    private static string? GetHeaderValue(HttpRequestData httpRequestData, string name)
    {
        return httpRequestData.Headers.TryGetValues(name, out var values)
            ? values.FirstOrDefault()
            : null;
    }

    private static HttpResponseData CreateErrorResponse(
        HttpRequestData httpRequestData,
        HttpStatusCode statusCode,
        string wwwAuthenticate,
        string message)
    {
        var response = httpRequestData.CreateResponse();
        response.StatusCode = statusCode;
        response.Headers.Add("WWW-Authenticate", wwwAuthenticate);
        response.Body.WriteAsync(System.Text.Encoding.UTF8.GetBytes(message)).GetAwaiter().GetResult();
        return response;
    }

    private static async Task WriteErrorAndStopAsync(
        FunctionContext context,
        HttpRequestData httpRequestData,
        HttpStatusCode statusCode,
        string wwwAuthenticate,
        string message)
    {
        context.GetInvocationResult().Value =
            CreateErrorResponse(httpRequestData, statusCode, wwwAuthenticate, message);
        await Task.CompletedTask;
    }
}
