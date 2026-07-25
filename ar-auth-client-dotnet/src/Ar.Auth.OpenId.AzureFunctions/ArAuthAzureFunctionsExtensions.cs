using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Ar.Auth.OpenId.AzureFunctions;

/// <summary>
/// Extension methods for integrating ArAuth middleware into Azure Functions Isolated Worker.
/// </summary>
public static class ArAuthAzureFunctionsExtensions
{
    /// <summary>
    /// Registers ArAuth services and adds the authentication middleware to the
    /// Azure Functions Isolated Worker pipeline.
    /// </summary>
    /// <param name="builder">The IFunctionsWorkerApplicationBuilder.</param>
    /// <param name="configure">Optional action to configure ArAuthOptions.</param>
    /// <param name="configureMiddleware">Optional action to configure middleware-specific options (audience, roles, scopes).</param>
    /// <returns>The builder for chaining.</returns>
    public static IFunctionsWorkerApplicationBuilder UseArAuth(
        this IFunctionsWorkerApplicationBuilder builder,
        Action<ArAuthOptions>? configure = null,
        Action<ArAuthMiddlewareOptions>? configureMiddleware = null)
    {
        var options = new ArAuthOptions();
        configure?.Invoke(options);

        var middlewareOptions = new ArAuthMiddlewareOptions();
        configureMiddleware?.Invoke(middlewareOptions);

        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton(middlewareOptions);
        builder.Services.AddSingleton<IArAuthClient>(sp =>
        {
            var httpClientFactory = sp.GetService<IHttpClientFactory>();
            var httpClient = httpClientFactory?.CreateClient("ArAuth") ?? new HttpClient();
            return new ArAuthClient(options, httpClient);
        });

        builder.UseMiddleware<ArAuthMiddleware>();

        return builder;
    }
}
