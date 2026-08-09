using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Ar.Auth.OpenId.AzureFunctions;

/// <summary>
/// Extension methods for integrating ArAuth middleware into Azure Functions Isolated Worker.
/// </summary>
public static class ArAuthAzureFunctionsExtensions
{
    /// <summary>
    /// Adds the ArAuth middleware to the Azure Functions Isolated Worker pipeline.
    /// You must call AddArAuth on IServiceCollection before calling this.
    /// </summary>
    public static IFunctionsWorkerApplicationBuilder UseArAuth(this IFunctionsWorkerApplicationBuilder builder)
    {
        builder.UseMiddleware<ArAuthMiddleware>();
        return builder;
    }

    /// <summary>
    /// Registers ArAuth services and configuration to the IServiceCollection using a provided instance.
    /// </summary>
    public static IServiceCollection AddArAuth(this IServiceCollection services, ArAuthOptions options)
    {
        services.AddSingleton(options);
        AddClient(services);
        return services;
    }

    /// <summary>
    /// Registers ArAuth services and configuration to the IServiceCollection using IConfiguration.
    /// </summary>
    public static IServiceCollection AddArAuth(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddSingleton(sp => 
        {
            var options = new ArAuthOptions();
            configuration.Bind(options);
            return options;
        });

        AddClient(services);
        return services;
    }

    /// <summary>
    /// Registers ArAuth services and configuration to the IServiceCollection using an action.
    /// </summary>
    public static IServiceCollection AddArAuth(this IServiceCollection services, Action<ArAuthOptions>? configure = null)
    {
        services.AddSingleton(sp => 
        {
            var options = new ArAuthOptions();
            configure?.Invoke(options);
            return options;
        });

        AddClient(services);
        return services;
    }

    /// <summary>
    /// Registers ArAuth services and configuration to the IServiceCollection using an action with IServiceProvider.
    /// </summary>
    public static IServiceCollection AddArAuth(this IServiceCollection services, Action<IServiceProvider, ArAuthOptions>? configure)
    {
        services.AddSingleton(sp => 
        {
            var options = new ArAuthOptions();
            configure?.Invoke(sp, options);
            return options;
        });

        AddClient(services);
        return services;
    }

    private static void AddClient(IServiceCollection services)
    {
        services.AddSingleton<IArAuthClient>(sp =>
        {
            var httpClientFactory = sp.GetService<IHttpClientFactory>();
            var httpClient = httpClientFactory?.CreateClient("ArAuth") ?? new HttpClient();
            var authOptions = sp.GetService<ArAuthOptions>() ?? new ArAuthOptions();
            return new ArAuthClient(authOptions, httpClient);
        });
    }
}
