// ─────────────────────────────────────────────────────────────────────────────
// ArAuth BFF sample — the same-domain topology from docs/cookie-auth-plan.md §5.
//
// The API processes the OIDC login callback and issues an app-local HttpOnly
// session cookie. No access/refresh/ID token ever reaches JavaScript; the SPA
// (wwwroot/index.html) is two links, a boot probe, and an XSRF header wrapper.
//
// Run it:
//   1) Register a public client on the auth server (PKCE, no secret) whose
//      redirect_uri is  <PublicBaseUrl or --urls> + /auth/callback
//   2) dotnet run --project samples/BffSample --urls https://localhost:8443
//      with appsettings or environment variables:
//        ArAuth__ClientId=my-app
//        Bff__PublicBaseUrl=https://localhost:8443   (optional, no proxy here)
//   3) open https://localhost:8443/  → "Sign in" → boot probe shows your sub.
//
// PRODUCTION NOTE: the session ticket and parked refresh token are encrypted
// with DataProtection. Multi-instance or restarting apps MUST share the key
// ring (Key Vault / blob / Redis) or every deploy logs everyone out:
//
//   builder.Services.AddDataProtection()
//       .PersistKeysToAzureBlobStorage(...)
//       .ProtectKeysWithAzureKeyVault(...);
// ─────────────────────────────────────────────────────────────────────────────

using System.Security.Claims;
using Ar.Auth.OpenId.AspNetCore;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

var clientId = builder.Configuration["ArAuth:ClientId"]
    ?? throw new InvalidOperationException(
        "Set ArAuth:ClientId — the public client registered on the auth server (PKCE, no secret).");

builder.Services.AddArAuth(options =>
{
    // Default authority: https://auth.adolfrey.com/api (override with ArAuth:Authority).
    options.ClientId = clientId;
})
.AddArAuthBff(bff =>
{
    // Only needed when the public URL differs from what the pipeline sees —
    // e.g. behind a reverse proxy that strips the /application1/api prefix.
    // Cookies are then path-scoped to PublicBaseUrl's path automatically.
    var publicBase = builder.Configuration["Bff:PublicBaseUrl"];
    if (!string.IsNullOrEmpty(publicBase))
    {
        bff.PublicBaseUrl = publicBase;
    }
});

builder.Services.AddAuthorization();

var app = builder.Build();

// Static SPA first: no auth machinery on the wire for index.html itself.
app.UseDefaultFiles();
app.UseStaticFiles();

// Required order (README): authentication → BFF routes → authorization.
app.UseAuthentication();
app.UseArAuthBff();
app.UseAuthorization();

// The SPA's boot probe.
app.MapGet("/me", [Authorize] (ClaimsPrincipal user) => Results.Json(new
{
    sub = user.FindFirst("sub")?.Value,
    claims = user.Claims.Select(c => new { c.Type, c.Value })
}));

// Unsafe-request demo: enforced signed double-submit XSRF header (X-CSRF-Token).
app.MapPost("/submit", [Authorize] () => Results.Text("accepted", "text/plain"));

app.Run();
