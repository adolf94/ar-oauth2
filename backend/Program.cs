using System;
using System.Net.Http;
using Microsoft.Azure.Cosmos;
using Microsoft.EntityFrameworkCore;
using Azure.Identity;
using backend.Data;
using backend.Services;
using backend.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;

var host = new HostBuilder()
    .ConfigureFunctionsWebApplication()
    .ConfigureServices((builder, services) =>
    {
        var appConfig = new backend.Configuration.AppConfig();
        builder.Configuration.GetSection("AppConfig").Bind(appConfig);

        // If GoogleClientId is at the root of Values, bind it manually if not already bound
        if (string.IsNullOrEmpty(appConfig.Google.ClientId))
        {
            appConfig.Google.ClientId = builder.Configuration["GoogleClientId"] ?? "dev-google-client-id";
        }

        if (string.IsNullOrEmpty(appConfig.Cosmos.Endpoint))
        {
            appConfig.Cosmos.Endpoint = "https://localhost:8081/";
        }

        Console.WriteLine($"[DEBUG] Using Cosmos Database: '{appConfig.Cosmos.DatabaseName}' at '{appConfig.Cosmos.Endpoint}'");

        // Pass configuration to the DbContext
        services.AddDbContext<AppDbContext>(options =>
        {
            // Log SQL-like queries to the console
            options.LogTo(Console.WriteLine, Microsoft.Extensions.Logging.LogLevel.Information)
                   .EnableSensitiveDataLogging();

            var configureCosmos = (Microsoft.EntityFrameworkCore.Infrastructure.CosmosDbContextOptionsBuilder o) =>
            {
                o.ConnectionMode(ConnectionMode.Gateway);
                o.HttpClientFactory(() => new HttpClient(new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                }));
            };

            if (string.IsNullOrEmpty(appConfig.Cosmos.Key))
            {
                // Use Managed Identity if NO key is provided
                options.UseCosmos(appConfig.Cosmos.Endpoint, new DefaultAzureCredential(), appConfig.Cosmos.DatabaseName, configureCosmos);
            }
            else
            {
                // Use Key if provided
                options.UseCosmos(appConfig.Cosmos.Endpoint, appConfig.Cosmos.Key, appConfig.Cosmos.DatabaseName, configureCosmos);
            }
        });

        // Register Services
        services.AddHttpClient();
        services.AddSingleton(appConfig);
        services.AddSingleton<RsaKeyService>();
        services.AddScoped<UserService>();
        services.AddScoped<ClientService>();
        services.AddScoped<AuthCodeService>();
        services.AddScoped<TokenService>();

        services.AddPasswordlessSdk(options =>
        {
            options.ApiSecret = appConfig.Passwordless.ApiSecret;
            options.ApiUrl = appConfig.Passwordless.ApiUrl;
        });
    })
    .Build();

host.Run();
