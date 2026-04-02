using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using backend.Models;

namespace backend.Services
{
    public interface IUserClientScopeService
    {
        Task<List<UserClientScope>> GetUserScopesAsync(string userId);
        Task<UserClientScope> AssignScopeAsync(string userId, string clientId, string scope);
        Task<bool> RemoveScopeAsync(Guid id);
    }
}
