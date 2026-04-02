using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using backend.Models;

namespace backend.Services
{
    public interface IRoleDefinitionService
    {
        Task<List<RoleDefinition>> GetRolesByClientAsync(string clientId);
        Task<RoleDefinition> CreateRoleAsync(string clientId, string name, string? description);
        Task<bool> DeleteRoleAsync(Guid id);
    }
}
