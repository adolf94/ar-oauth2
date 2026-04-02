using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Services
{
    public class ApplicationScopeService : IApplicationScopeService
    {
        private readonly AppDbContext _dbContext;

        public ApplicationScopeService(AppDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<List<ApplicationScope>> GetScopesByClientAsync(string clientId)
        {
            return await _dbContext.ApplicationScopes
                .Where(s => s.ClientId == clientId)
                .ToListAsync();
        }

        public async Task<ApplicationScope> CreateScopeAsync(string clientId, string name, string? description, bool isAdminApproved = false, bool isClientOnly = false)
        {
            var existing = await _dbContext.ApplicationScopes
                .Where(s => s.ClientId == clientId && s.Name == name)
                .AnyAsync();
                
            if (existing) throw new Exception("Scope already exists for this client");

            var scope = new ApplicationScope
            {
                ClientId = clientId,
                Name = name,
                Description = description,
                IsAdminApproved = isAdminApproved,
                IsClientOnly = isClientOnly
            };

            _dbContext.ApplicationScopes.Add(scope);
            await _dbContext.SaveChangesAsync();
            return scope;
        }

        public async Task<bool> DeleteScopeAsync(Guid scopeId)
        {
            var scope = await _dbContext.ApplicationScopes.FindAsync(scopeId);
            if (scope == null) return false;

            _dbContext.ApplicationScopes.Remove(scope);
            await _dbContext.SaveChangesAsync();
            return true;
        }

        public async Task<List<ApplicationScope>> GetAllScopesAsync()
        {
            return await _dbContext.ApplicationScopes.ToListAsync();
        }
    }
}
