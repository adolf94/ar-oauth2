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

                // 5. Ensure Llamalabs Automate client exists
                var llamalabsAutomateId = "llamalabs-automate";
                var llamalabsAutomate = await _dbContext.Clients.FirstOrDefaultAsync(c => c.ClientId == llamalabsAutomateId);
                if (llamalabsAutomate == null)
                {
                    _logger.LogInformation("Seeding Llamalabs Automate client: {ClientId}", llamalabsAutomateId);
                    llamalabsAutomate = new Client
                    {
                        ClientId = llamalabsAutomateId,
                        RedirectUris = new List<string> {
                            "https://id.adolfrey.com/profile/automate/callback",
                            "https://localhost:5174/profile/automate/callback",
                            "llamalabs-automate",
                            "automate://callback"
                        },
                        AllowedScopes = new List<string> { "openid", "profile", "email", "offline_access" }
                    };
                    _dbContext.Clients.Add(llamalabsAutomate);
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
