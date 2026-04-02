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

                        RedirectUris = new List<string> {
                            "https://auth.adolfrey.com/auth/callback",
                            "https://localhost:5174/auth/callback",
                            "https://localhost:5174/"
                        },
                        AllowedScopes = new List<string> { "openid", "profile", "admin", "manage" }
                    };

                    _dbContext.Clients.Add(managementClient);
                }

                // Ensure users:read:all scope exists for this client
                var scopeName = "users:read:all";
                var managementScope = await _dbContext.ApplicationScopes.FirstOrDefaultAsync(s => s.ClientId == managementClientId && s.Name == scopeName);
                if (managementScope == null)
                {
                    _logger.LogInformation("Seeding management scope: {ScopeName}", scopeName);
                    managementScope = new ApplicationScope
                    {
                        Id = Guid.NewGuid(),
                        ClientId = managementClientId,
                        Name = scopeName,
                        Description = "Management scope to read all user data and linked accounts.",
                        IsAdminApproved = true,
                        IsClientOnly = true
                    };
                    _dbContext.ApplicationScopes.Add(managementScope);
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
