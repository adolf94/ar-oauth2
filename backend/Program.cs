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
using Microsoft.Extensions.Logging;
using Microsoft.Azure.Functions.Worker;
using Microsoft.ApplicationInsights.Extensibility;

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

            if (string.IsNullOrEmpty(appConfig.Cosmos.Key))
            {
                // Use Managed Identity if NO key is provided
                options.UseCosmos(appConfig.Cosmos.Endpoint, new DefaultAzureCredential(), appConfig.Cosmos.DatabaseName);
            }
            else
            {
                // Use Key if provided
                options.UseCosmos(appConfig.Cosmos.Endpoint, appConfig.Cosmos.Key, appConfig.Cosmos.DatabaseName);
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
        services.AddScoped<ApplicationScopeService>();
        services.AddScoped<RoleDefinitionService>();
        services.AddScoped<UserClientScopeService>();
        services.AddScoped<CrossAppTrustService>();
        services.AddScoped<DatabaseInitializer>();
        services.AddScoped<LogService>();

        services.AddPasswordlessSdk(options =>
        {
            options.ApiSecret = appConfig.Passwordless.ApiSecret;
            options.ApiUrl = appConfig.Passwordless.ApiUrl;
        });

        // Add Application Insights
        services.AddApplicationInsightsTelemetryWorkerService();
        services.ConfigureFunctionsApplicationInsights();

        // Add CORS
        services.AddCors(options =>
        {
            options.AddDefaultPolicy(policy =>
            {
                policy.WithOrigins("https://id.adolfrey.com", "https://localhost:5174")
                      .AllowAnyHeader()
                      .AllowAnyMethod()
                      .AllowCredentials();
            });
        });
    })
    .ConfigureLogging(logging =>
    {
        logging.AddApplicationInsights();
        logging.AddFilter<Microsoft.Extensions.Logging.ApplicationInsights.ApplicationInsightsLoggerProvider>("", LogLevel.Information);
    })
    .Build();


// Initialize the database (seed clients)
using (var scope = host.Services.CreateScope())
{
    var initializer = scope.ServiceProvider.GetRequiredService<DatabaseInitializer>();
    await initializer.InitializeAsync();
}

await host.RunAsync();
