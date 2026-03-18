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
                            "https://localhost:5174/auth/callback", // Assuming localhost:5174 for second app dev
                            "https://localhost:5174/"
                        },
                        AllowedScopes = new List<string> { "openid", "profile", "admin", "manage" }
                    };

                    _dbContext.Clients.Add(managementClient);
                }
                if (!managementClient.RedirectUris.Contains("https://auth.adolfrey.com/auth/callback"))
                {
                    managementClient.RedirectUris.Add("https://auth.adolfrey.com/auth/callback");
                }

                // --- Ar-Go Implementation ---
                var arGoWebId = "ar-go-web";
                var arGoApiId = "ar-go-api";

                // 1. Ensure Ar-Go Web Client exists
                var arGoWeb = await _dbContext.Clients.FirstOrDefaultAsync(c => c.ClientId == arGoWebId);
                if (arGoWeb == null)
                {
                    _logger.LogInformation("Seeding Ar-Go Web client: {ClientId}", arGoWebId);
                    arGoWeb = new Client
                    {
                        ClientId = arGoWebId,
                        RedirectUris = new List<string> {
                            "https://localhost:5174/auth/callback",
                            "https://localhost:5174/",
                            "https://argo.adolfrey.com/auth/callback"
                        },
                        AllowedScopes = new List<string> { "openid", "profile", "email", "offline_access", $"api://{arGoApiId}/user" }
                    };
                    _dbContext.Clients.Add(arGoWeb);
                }

                // 2. Ensure Ar-Go API Client exists (as a resource)
                var arGoApi = await _dbContext.Clients.FirstOrDefaultAsync(c => c.ClientId == arGoApiId);
                if (arGoApi == null)
                {
                    _logger.LogInformation("Seeding Ar-Go API client: {ClientId}", arGoApiId);
                    arGoApi = new Client
                    {
                        ClientId = arGoApiId,
                        AllowedScopes = new List<string> { "openid" }
                    };
                    _dbContext.Clients.Add(arGoApi);
                }

                // 3. Ensure "user" scope exists for Ar-Go API
                var userScope = await _dbContext.ApplicationScopes.FirstOrDefaultAsync(s => s.ClientId == arGoApiId && s.Name == "user");
                if (userScope == null)
                {
                    _logger.LogInformation("Seeding 'user' scope for Ar-Go API");
                    userScope = new ApplicationScope
                    {
                        ClientId = arGoApiId,
                        Name = "user",
                        Description = "Access to user-specific Ar-Go data",
                        IsAdminApproved = true // Auto-grant to everyone for now
                    };
                    _dbContext.ApplicationScopes.Add(userScope);
                }

                // 4. Ensure Cross-App Trust exists: ar-go-web -> ar-go-api / user
                var trust = await _dbContext.CrossAppTrusts.FirstOrDefaultAsync(t => t.RequestingClientId == arGoWebId && t.TargetClientId == arGoApiId && t.ScopeName == "user");
                if (trust == null)
                {
                    _logger.LogInformation("Seeding Cross-App Trust: {Requesting} -> {Target} / {Scope}", arGoWebId, arGoApiId, "user");
                    trust = new CrossAppTrust
                    {
                        RequestingClientId = arGoWebId,
                        TargetClientId = arGoApiId,
                        ScopeName = "user",
                        IsApproved = true
                    };
                    _dbContext.CrossAppTrusts.Add(trust);
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
