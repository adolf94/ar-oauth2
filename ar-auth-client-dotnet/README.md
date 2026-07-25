# Ar.Auth.OpenId

A .NET 8 SDK for [Atlas Rig Auth](https://auth.adolfrey.com) (an OIDC/OAuth 2.0 provider), supporting token verification, code exchange, credentials grants, and framework integrations (ASP.NET Core and Azure Functions Isolated Worker).

## Packages

| Package | Description |
|---|---|
| `Ar.Auth.OpenId` | Core client: JWKS signature verification, token validation, OAuth 2.0 flows. |
| `Ar.Auth.OpenId.AspNetCore` | ASP.NET Core JWT Bearer authentication integration. |
| `Ar.Auth.OpenId.AzureFunctions` | Azure Functions Isolated Worker middleware. |

## Features

- **Dynamic JWKS Signature Verification**: Automatically retrieves, caches, and rotates RSA signing keys from the provider's OIDC discovery endpoint.
- **Robust Token Validation**: Validates JWT claims (expiration, issuer, and RS256 signature verification).
- **Default Authority**: Automatically defaults to `https://auth.adolfrey.com/api`.
- **Multiple OAuth 2.0 / OIDC Grants**: Supports Authorization Code flow, Refresh Token grant, and Client Credentials (machine-to-machine) grant.
- **Native Framework Integrations**: ASP.NET Core and Azure Functions Isolated Worker.

## Basic Usage

### Verify a Token (Standalone)

```csharp
using Ar.Auth.OpenId;

// Default authority: https://auth.adolfrey.com/api
var client = new ArAuthClient();

try
{
    var principal = await client.VerifyTokenAsync("eyJhbGciOiJSUzI1Ni...");
    Console.WriteLine($"User: {principal.Identity?.Name}");
}
catch (Ar.Auth.OpenId.Exceptions.TokenValidationException ex)
{
    Console.WriteLine($"Token invalid: {ex.Message}");
}
```

> **Note:** Token verification does NOT require `ClientId` or `ClientSecret`. It only needs the Authority URL to fetch the public signing keys.

### With Dependency Injection

```csharp
using Ar.Auth.OpenId;

builder.Services.AddArAuth(options =>
{
    options.Authority = "https://auth.adolfrey.com/api";
    // ClientId/ClientSecret only needed for token exchange flows
});

// Inject IArAuthClient anywhere
public class MyService
{
    private readonly IArAuthClient _auth;
    public MyService(IArAuthClient auth) => _auth = auth;
}
```

---

## ASP.NET Core Integration

The simplest way to protect an ASP.NET Core Web API:

```csharp
using Ar.Auth.OpenId.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add ArAuth JWT Bearer authentication
builder.Services.AddArAuth(options =>
{
    options.Authority = "https://auth.adolfrey.com/api";
});
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/profile", (ClaimsPrincipal user) =>
{
    return Results.Ok(new { sub = user.FindFirst("sub")?.Value });
}).RequireAuthorization();

app.Run();
```

---

## Azure Functions Integration

For Azure Functions using the **Isolated Worker Model**:

```csharp
using Ar.Auth.OpenId.AzureFunctions;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Hosting;

var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults(worker =>
    {
        worker.UseArAuth(
            configure: options =>
            {
                options.Authority = "https://auth.adolfrey.com/api";
            },
            configureMiddleware: middleware =>
            {
                middleware.RequiredRoles = new[] { "admin" };
            }
        );
    })
    .Build();

host.Run();
```

Then in your function, access the authenticated user via `FunctionContext.Items`:

```csharp
using System.Security.Claims;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;

public class HelloFunction
{
    [Function("Hello")]
    public HttpResponseData Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get")] HttpRequestData req,
        FunctionContext context)
    {
        var user = context.Items["ArAuthUser"] as ClaimsPrincipal;
        var response = req.CreateResponse();
        response.StatusCode = System.Net.HttpStatusCode.OK;
        response.Body.Write(
            System.Text.Encoding.UTF8.GetBytes($"Hello, {user?.FindFirst("sub")?.Value}!"));
        return response;
    }
}
```

---

## OAuth 2.0 Token Exchange Flows

These flows **do** require `ClientId` and/or `ClientSecret`.

### Authorization Code Exchange

```csharp
var client = new ArAuthClient(new ArAuthOptions
{
    ClientId = "my-client-id",
    ClientSecret = "my-client-secret"
});

var tokens = await client.ExchangeCodeAsync(
    code: "auth_code_from_redirect",
    redirectUri: "https://myapp.com/callback",
    codeVerifier: "pkce_verifier_if_used"
);

Console.WriteLine($"Access Token: {tokens.AccessToken}");
```

### Refresh Token

```csharp
var refreshed = await client.RefreshTokenAsync("refresh_token_value");
Console.WriteLine($"New Access Token: {refreshed.AccessToken}");
```

### Client Credentials (M2M)

```csharp
var tokenResponse = await client.ClientCredentialsAsync(scope: "api://other-app/read:data");
Console.WriteLine($"M2M Token: {tokenResponse.AccessToken}");
```

## License

This project is licensed under the MIT License.
