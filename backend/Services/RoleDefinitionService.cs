using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Services
{
    public class RoleDefinitionService : IRoleDefinitionService
    {
        private readonly AppDbContext _dbContext;

        public RoleDefinitionService(AppDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<List<RoleDefinition>> GetRolesByClientAsync(string clientId)
        {
            return await _dbContext.RoleDefinitions
                .Where(r => r.ClientId == clientId)
                .ToListAsync();
        }

        public async Task<RoleDefinition> CreateRoleAsync(string clientId, string name, string? description)
        {
            var existing = await _dbContext.RoleDefinitions
                .Where(r => r.ClientId == clientId && r.Name == name)
                .FirstOrDefaultAsync() != null;
            
            if (existing) throw new Exception("Role already exists for this application");

            var role = new RoleDefinition
            {
                ClientId = clientId,
                Name = name,
                Description = description
            };

            _dbContext.RoleDefinitions.Add(role);
            await _dbContext.SaveChangesAsync();
            return role;
        }

        public async Task<bool> DeleteRoleAsync(Guid id)
        {
            var role = await _dbContext.RoleDefinitions.FirstOrDefaultAsync(r => r.Id == id);
            if (role == null) return false;

            _dbContext.RoleDefinitions.Remove(role);
            await _dbContext.SaveChangesAsync();
            return true;
        }
    }
}
