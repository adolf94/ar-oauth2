using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Services
{
    public class UserClientScopeService
    {
        private readonly AppDbContext _dbContext;

        public UserClientScopeService(AppDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<List<UserClientScope>> GetUserScopesAsync(string userId)
        {
            return await _dbContext.UserClientScopes
                .Where(s => s.UserId == userId)
                .ToListAsync();
        }

        public async Task<UserClientScope> AssignScopeAsync(string userId, string clientId, string scope)
        {
            var existing = await _dbContext.UserClientScopes
                .Where(s => s.UserId == userId && s.ClientId == clientId && s.Scope == scope)
                .FirstOrDefaultAsync() != null;

            if (existing) throw new Exception("Scope already assigned to user for this client");

            var mapping = new UserClientScope
            {
                UserId = userId,
                ClientId = clientId,
                Scope = scope
            };

            _dbContext.UserClientScopes.Add(mapping);
            await _dbContext.SaveChangesAsync();
            return mapping;
        }

        public async Task<bool> RemoveScopeAsync(Guid id)
        {
            var mapping = await _dbContext.UserClientScopes.FindAsync(id);
            if (mapping == null) return false;

            _dbContext.UserClientScopes.Remove(mapping);
            await _dbContext.SaveChangesAsync();
            return true;
        }
    }
}
