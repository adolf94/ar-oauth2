using Microsoft.Extensions.DependencyInjection;

namespace Ar.Auth.OpenId;

/// <summary>
/// Extension methods for registering ArAuth services in the DI container.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the ArAuth client in the DI container with default options.
    /// </summary>
    public static IServiceCollection AddArAuth(this IServiceCollection services)
    {
        return services.AddArAuth(_ => { });
    }

    /// <summary>
    /// Registers the ArAuth client in the DI container with custom options.
    /// </summary>
    public static IServiceCollection AddArAuth(this IServiceCollection services, Action<ArAuthOptions> configure)
    {
        var options = new ArAuthOptions();
        configure(options);

        services.AddSingleton(options);
        services.AddSingleton<IArAuthClient>(sp =>
        {
            var httpClientFactory = sp.GetService<IHttpClientFactory>();
            var httpClient = httpClientFactory?.CreateClient("ArAuth") ?? new HttpClient();
            return new ArAuthClient(options, httpClient);
        });

        return services;
    }
}
