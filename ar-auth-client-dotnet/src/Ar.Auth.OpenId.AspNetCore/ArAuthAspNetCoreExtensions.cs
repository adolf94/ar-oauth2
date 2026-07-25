using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Ar.Auth.OpenId.AspNetCore;

/// <summary>
/// Extension methods for integrating ArAuth with ASP.NET Core authentication.
/// </summary>
public static class ArAuthAspNetCoreExtensions
{
    /// <summary>
    /// Adds ArAuth JWT Bearer authentication to the ASP.NET Core pipeline.
    /// Configures JwtBearer to validate tokens against the Atlas Rig OIDC provider.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional action to configure ArAuthOptions.</param>
    /// <returns>The AuthenticationBuilder for further configuration.</returns>
    public static AuthenticationBuilder AddArAuth(
        this IServiceCollection services,
        Action<ArAuthOptions>? configure = null)
    {
        var options = new ArAuthOptions();
        configure?.Invoke(options);

        // Register the core ArAuth client for DI
        services.AddSingleton(options);
        services.AddSingleton<IArAuthClient>(sp =>
        {
            var httpClientFactory = sp.GetService<IHttpClientFactory>();
            var httpClient = httpClientFactory?.CreateClient("ArAuth") ?? new HttpClient();
            return new ArAuthClient(options, httpClient);
        });

        var authority = options.NormalizedAuthority;
        var metadataAddress = $"{authority}/.well-known/openid-configuration";

        return services
            .AddAuthentication(authOptions =>
            {
                authOptions.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                authOptions.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(jwtOptions =>
            {
                jwtOptions.Authority = authority;
                jwtOptions.MetadataAddress = metadataAddress;
                jwtOptions.RequireHttpsMetadata = !authority.StartsWith("http://");

                jwtOptions.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidIssuer = authority,
                    ValidateAudience = !string.IsNullOrEmpty(options.ClientId),
                    ValidAudience = options.ClientId,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromSeconds(30),
                };
            });
    }

    /// <summary>
    /// Adds ArAuth JWT Bearer authentication with audience validation.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="audience">The expected audience claim for token validation.</param>
    /// <param name="configure">Optional action to configure additional ArAuthOptions.</param>
    /// <returns>The AuthenticationBuilder for further configuration.</returns>
    public static AuthenticationBuilder AddArAuth(
        this IServiceCollection services,
        string audience,
        Action<ArAuthOptions>? configure = null)
    {
        return services.AddArAuth(options =>
        {
            configure?.Invoke(options);
            options.ClientId = audience;
        });
    }
}
