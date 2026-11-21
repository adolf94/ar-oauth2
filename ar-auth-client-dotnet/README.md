# Ar.Auth.OpenId

A .NET SDK for [Atlas Rig Auth](https://auth.adolfrey.com) (an OIDC/OAuth 2.0 provider), supporting token verification, code exchange, credentials grants, and framework integrations (ASP.NET Core and Azure Functions Isolated Worker).

Packages target **.NET 8, 9, and 10** (LTS/STS/LTS). See [CHANGELOG.md](CHANGELOG.md) for release history.

## Packages

| Package | Description |
|---|---|
| `Ar.Auth.OpenId` | Core client: JWKS signature verification, token validation, OAuth 2.0 flows. |
| `Ar.Auth.OpenId.AspNetCore` | ASP.NET Core integration: JWT Bearer auth, BFF same-domain sessions (`AddArAuthBff`), session-cookie fallback. |
| `Ar.Auth.OpenId.AzureFunctions` | Azure Functions Isolated Worker middleware. |

## Features

- **Dynamic JWKS Signature Verification**: Automatically retrieves, caches, and rotates RSA signing keys from the provider's OIDC discovery endpoint.
- **Robust Token Validation**: Validates JWT claims (expiration, issuer, and RS256 signature verification).
- **Default Authority**: Automatically defaults to `https://auth.adolfrey.com/api`.
- **Multiple OAuth 2.0 / OIDC Grants**: Supports Authorization Code flow, Refresh Token grant, and Client Credentials (machine-to-machine) grant.
- **Native Framework Integrations**: ASP.NET Core and Azure Functions Isolated Worker.
- **BFF Integration for Same-Domain Apps**: the API processes the OIDC login callback and issues an app-local **HttpOnly session cookie** — no access, refresh, or ID token ever reaches JavaScript (`AddArAuthBff`; see below).
- **Optional Session-Cookie Authentication**: On same-site APIs, the auth server's `ar_auth_session` cookie can be accepted as a fallback credential when no Bearer header is present (opt-in; see below).

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

## BFF Integration — Same-Domain Apps (`AddArAuthBff`)

**The recommended same-domain integration.** For SPAs served from the same domain as
their API (e.g. the app at `https://apps.adolfrey.com/application1/`, its API at
`https://apps.adolfrey.com/application1/api/`), this SDK implements the
**BFF (Backend-for-Frontend)** pattern: the API processes the OIDC login callback and
issues an app-local HttpOnly session cookie. No token is ever held in JavaScript; the
SPA's entire auth surface is two links and a boot probe. No frontend auth library needed.

```csharp
using Ar.Auth.OpenId.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddArAuth(options =>
{
    options.Authority = "https://auth.adolfrey.com/api";
    options.ClientId = "my-app"; // public client registration (PKCE, no secret)
})
.AddArAuthBff(bff =>
{
    // Only needed behind a prefix-stripping reverse proxy, where the public URL
    // differs from what the app's pipeline sees:
    bff.PublicBaseUrl = "https://apps.adolfrey.com/application1/api";
});

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseArAuthBff();      // between UseAuthentication and UseAuthorization
app.UseAuthorization();

app.MapGet("/me", [Authorize] (ClaimsPrincipal user) =>
    Results.Ok(new { sub = user.FindFirst("sub")?.Value }));

app.Run();
```

**The flow.** Login is `GET /auth/login?returnUrl=/dashboard`: a 302 to the auth server
(authorization-code flow + PKCE; state, nonce, and correlation cookies are handled by the
framework's `AddOpenIdConnect` machinery). The auth server redirects back to
`GET /auth/callback` on the API, which validates the `id_token`, issues the app session
cookie, **parks the refresh token in its own encrypted cookie**, and 302s to the return
URL. `GET /auth/logout` clears every app-local cookie.

- **Silent renewal**: when the session expires while the parked refresh token is valid,
  the next request transparently re-issues both cookies — single-flight, so concurrent
  tabs cause exactly one refresh round-trip (the ar-auth server rotates refresh tokens
  on each use).
- **CSRF** (default on): `SameSite=Lax` cookies, an origin check, and a signed
  double-submit token — the SPA reads the `XSRF-TOKEN` cookie (readable by JS) and echoes
  it in the `X-CSRF-Token` header on unsafe requests. Sibling-subdomain cookie-tossing
  fails the signature check. `X-XSRF-TOKEN` is accepted as an Angular-style alias; set
  `BffOptions.Csrf = BffCsrfMode.Off` only if you know why.
- **Precedence**: an `Authorization: Bearer` header always wins over any cookie, so the
  same API keeps serving cross-domain Bearer clients unchanged — and 401 challenges stay
  `WWW-Authenticate: Bearer`.

**Options** (`BffOptions`): `LoginPath`/`CallbackPath`/`LogoutPath` (defaults
`/auth/login|callback|logout`), `PublicBaseUrl` (see above), `CookiePath` and
`CookieNamePrefix` (cookie isolation when several apps share one host — the prefix
defaults to the derived cookie path, e.g. `application1.` for `/application1/`), and
`SessionExpiry` (default 8 h, silently renewed while the refresh chain lives).

**The SPA contract** — the complete frontend auth code, no library:

```html
<a href="/auth/login?returnUrl=/dashboard">Sign in</a>
<a href="/auth/logout?returnUrl=/">Sign out</a>
```

```javascript
// Boot probe: 200 → signed in, 401 → render the signed-out state.
const res = await fetch("/me", { credentials: "same-origin" });

// Unsafe requests echo the readable XSRF-TOKEN cookie in a header.
function xsrfHeader(headers = {}) {
  const token = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/)?.[1];
  return token ? { ...headers, "X-CSRF-Token": token } : headers;
}

await fetch("/api/things", {
  method: "POST",
  credentials: "same-origin",
  headers: xsrfHeader({ "Content-Type": "application/json" }),
  body: JSON.stringify(payload)
});
```

A runnable version of exactly this contract lives in [`samples/BffSample`](samples/BffSample/).

**Extensibility**: five hooks around the flow — subclass `ArAuthHandler` and register it
with `AddArAuthBff<MyHandler>(...)` (constructor injection supported), or set the same
hooks as delegates on `bff.Events`: `OnLoginRedirectingAsync` (extra authorize
parameters), `OnAuthenticatedAsync` (enrich the principal, or `ctx.Reject(...)` to abort
the login without issuing a session), `OnRedirectingAsync`, `OnLogoutAsync`,
`OnRenewedAsync`. Base implementations own every security-critical step — overriding a
hook cannot skip it; not calling `base` only opts out of the delegate of the same name.

> **⚠ Deployment — DataProtection is load-bearing.**
> The session ticket and the parked refresh token are encrypted with ASP.NET Core
> `DataProtection`. With the default in-memory/local key storage, **every restart — and
> every instance without the shared key ring — silently invalidates all sessions.**
> Multi-instance or frequently-redeployed apps MUST share the key ring (Azure Key Vault,
> blob storage, or Redis via the `Microsoft.AspNetCore.DataProtection.*` packages).
> Renewal single-flight is per-process: horizontally scaled deployments need sticky
> sessions or a single BFF instance.

> **Local dev & proxies.** Cookies are `Secure` whenever the request is HTTPS
> (`SameAsRequest`), so plain-HTTP dev only behaves realistically against plain-HTTP
> mock authorities — otherwise use a local cert (`mkcert`) and `--urls https://…`.
> Behind a TLS-terminating proxy the app must see `X-Forwarded-Proto` (plus
> `X-Forwarded-Prefix` when the proxy strips a prefix), or set `PublicBaseUrl` explicitly.

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

## Session-Cookie Fallback (Legacy Shared-Domain Cookie)

> Same-domain apps should prefer the **BFF integration above**: it needs no shared
> `Domain` cookie, gives every app its own path-scoped session, and keeps refresh tokens
> server-side. The fallback below remains supported for the simpler topology where the
> auth server sets a session cookie with `Domain=.adolfrey.com` and sibling APIs honor
> it directly.

By default this library only accepts `Authorization: Bearer` credentials. It can also accept
the auth server's **session cookie** (`ar_auth_session`) as a fallback credential when no
Authorization header is present:

```csharp
options.Authority = "https://auth2.adolfrey.com/api";
options.AllowSessionCookie = true;                      // opt-in
options.CookieName = "ar_auth_session";                 // default shown
options.AllowedCookieOrigins = new[] { "https://app.adolfrey.com" }; // optional cross-origin allow-list
```

This works in **both** packages — the ASP.NET Core integration (a session scheme behind a
policy scheme, so `[Authorize]` keeps working) and the Azure Functions middleware (cookie
fallback before the 401).

**When this can work at all**: the API must share a registrable domain (site) with the auth
server — e.g. `auth2.adolfrey.com` + `api.adolfrey.com`, with the auth server setting the
cookie via `SessionCookieDomain` (`AppConfig.Jwt.SessionCookieDomain`). Browsers **never**
send the auth server's cookie to an API on a different domain, so for cross-domain APIs
Bearer tokens remain the only option.

Behavior details:

- **Bearer always wins**: a request with an `Authorization` header never consults the cookie.
- **CSRF guard**: the cookie is only honored when the request's `Origin`/`Referer` is
  same-origin (or in `AllowedCookieOrigins`). Browsers omit `Origin` on safe methods
  (GET/HEAD), so absence is allowed there; on POST/PUT/DELETE absence is rejected.
- **No privilege escalation**: session JWTs carry `sub`/`email`/`name` only — no roles or
  scopes — so `RequiredRoles`, `RequiredScopes`, and `[Authorize(Roles = ...)]` still fail
  cleanly for cookie-authenticated callers. The cookie answers "who is this user"; use
  Bearer tokens for anything privileged.
- The same-site `SameSite=Lax` policy on the cookie is sufficient for subdomain API calls;
  cross-site support (`SameSite=None`) is deliberately not offered (unreliable in Safari).

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
