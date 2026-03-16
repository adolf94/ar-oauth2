using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace backend.Services
{
    public class DatabaseInitializer
    {
        private readonly AppDbContext _dbContext;
        private readonly ILogger<DatabaseInitializer> _logger;

        public DatabaseInitializer(AppDbContext dbContext, ILogger<DatabaseInitializer> logger)
        {
            _dbContext = dbContext;
            _logger = logger;
        }

        public async Task InitializeAsync()
        {
            _logger.LogInformation("Initializing database and seeding system clients...");

            try
            {
                // Ensure the system client exists
                var systemClientId = "ar-auth-system";
                var systemClient = await _dbContext.Clients.FirstOrDefaultAsync(c => c.ClientId == systemClientId);

                if (systemClient == null)
                {
                    _logger.LogInformation("Seeding system client: {ClientId}", systemClientId);
                    
                    systemClient = new Client
                    {
                        Id = Guid.NewGuid(),
                        ClientId = systemClientId,
                        ClientSecrets = new List<ClientSecret>(), // Public client: no secrets
                        RedirectUris = new List<string> { 
                            "http://localhost:5173/auth/callback",
                            "http://localhost:5173/auth/popup-callback",
                            "http://localhost:5173/" 
                        },
                        AllowedScopes = new List<string> { "openid", "profile", "admin", "manage" }
                    };

                    _dbContext.Clients.Add(systemClient);
                }
                else
                {
                    // Ensure it stays a public client
                    if (systemClient.ClientSecrets != null && systemClient.ClientSecrets.Any())
                    {
                        _logger.LogInformation("Converting {ClientId} to a public client (removing secrets).", systemClientId);
                        systemClient.ClientSecrets.Clear();
                    }
                    if (!systemClient.RedirectUris.Contains("http://localhost:5173/auth/callback"))
                    {
                        systemClient.RedirectUris.Add("http://localhost:5173/auth/callback");
                    }
                    if (!systemClient.RedirectUris.Contains("http://localhost:5173/auth/popup-callback"))
                    {
                        systemClient.RedirectUris.Add("http://localhost:5173/auth/popup-callback");
                    }
                }

                // Ensure the management client exists
                var managementClientId = "ar-auth-management";
                var managementClient = await _dbContext.Clients.FirstOrDefaultAsync(c => c.ClientId == managementClientId);

                if (managementClient == null)
                {
                    _logger.LogInformation("Seeding management client: {ClientId}", managementClientId);
                    
                    managementClient = new Client
                    {
                        Id = Guid.NewGuid(),
                        ClientId = managementClientId,
                        ClientSecrets = new List<ClientSecret>(), // Public client
                        RedirectUris = new List<string> { 
                            "https://auth.adolfrey.com/auth/callback",
                            "http://localhost:5174/auth/callback", // Assuming localhost:5174 for second app dev
                            "http://localhost:5174/" 
                        },
                        AllowedScopes = new List<string> { "openid", "profile", "admin", "manage" }
                    };

                    _dbContext.Clients.Add(managementClient);
                }
                else
                {
                    if (!managementClient.RedirectUris.Contains("https://auth.adolfrey.com/auth/callback"))
                    {
                        managementClient.RedirectUris.Add("https://auth.adolfrey.com/auth/callback");
                    }
                }

                await _dbContext.SaveChangesAsync();
                _logger.LogInformation("Database initialization complete.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred during database initialization.");
            }
        }
    }
}
