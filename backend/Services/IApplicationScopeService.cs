using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using backend.Models;

namespace backend.Services
{
    public interface IApplicationScopeService
    {
        Task<List<ApplicationScope>> GetScopesByClientAsync(string clientId);
        Task<ApplicationScope> CreateScopeAsync(string clientId, string name, string? description, bool isAdminApproved = false, bool isClientOnly = false, bool allowPat = true, int? maxAccessTokenLifetime = null);
        Task<bool> DeleteScopeAsync(Guid scopeId);
        Task<List<ApplicationScope>> GetAllScopesAsync();
    }
}
