using System.Net;
using System.Security.Claims;
using Ar.Auth.OpenId.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;

namespace Ar.Auth.OpenId.Tests;

/// <summary>
/// The app under test: a minimal same-domain API wired with AddArAuth + AddArAuthBff,
/// running in-proc on a random loopback port. Mirrors the consuming-app shape from
/// docs/cookie-auth-plan.md §5 (me + public endpoints).
/// </summary>
public sealed class BffTestApp : IAsyncDisposable
{
    private readonly WebApplication _app;

    private BffTestApp(WebApplication app)
    {
        _app = app;
        BaseUrl = app.Services
            .GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!
            .Addresses.First()
            .TrimEnd('/');
    }

    public string BaseUrl { get; }

    public T GetService<T>() where T : notnull
        => _app.Services.GetRequiredService<T>();

    public static async Task<BffTestApp> StartAsync(
        string authority,
        Action<BffOptions>? configureBff = null,
        Action<IServiceCollection>? configureServices = null,
        Action<AuthenticationBuilder>? configureAuth = null,
        Action<ArAuthOptions>? configureArAuth = null)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(o => o.Listen(IPAddress.Loopback, 0));
        builder.Services.AddAuthorization(); // CreateSlimBuilder skips the web-defaults
        configureServices?.Invoke(builder.Services);

        // Explicit call: the test namespace walks up to Ar.Auth.OpenId, whose
        // core-package AddArAuth(IServiceCollection) overload would otherwise shadow
        // the AspNetCore one that returns the AuthenticationBuilder we chain on.
        var auth = ArAuthAspNetCoreExtensions
            .AddArAuth(builder.Services, o =>
            {
                o.Authority = authority;
                o.ClientId = "bff-test-client";
                configureArAuth?.Invoke(o);
            });

        if (configureAuth != null)
        {
            configureAuth(auth);
        }
        else
        {
            auth.AddArAuthBff(configureBff);
        }

        var app = builder.Build();
        app.UseAuthentication();
        app.UseArAuthBff();
        app.UseAuthorization();

        app.MapGet("/me", [Authorize] (ClaimsPrincipal user) =>
            Results.Text(user.FindFirst("sub")?.Value ?? "anon", "text/plain"));
        app.MapGet("/claims", [Authorize] (ClaimsPrincipal user) =>
            Results.Json(user.Claims.Select(c => new { c.Type, c.Value })));
        app.MapGet("/public", () => Results.Text("ok", "text/plain"));
        app.MapPost("/submit", [Authorize] () => Results.Text("accepted", "text/plain"));

        await app.StartAsync();
        return new BffTestApp(app);
    }

    public ValueTask DisposeAsync() => _app.DisposeAsync();
}
