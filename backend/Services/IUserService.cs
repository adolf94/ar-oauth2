using System.Collections.Generic;
using System.Threading.Tasks;
using backend.Models;

namespace backend.Services
{
    public interface IUserService
    {
        Task<List<User>> GetAllUsersAsync();
        Task<User?> GetByEmailAsync(string email);
        Task<User?> GetByExternalIdentityAsync(string provider, string providerId);
        Task<User?> GetByIdAsync(string id);
        Task<User> CreateUserAsync(
            string email, 
            string? mobileNumber, 
            List<string> roles, 
            string? externalProvider = null, 
            string? externalId = null, 
            string? name = null,
            string? sub = null,
            string? externalEmail = null,
            string? externalMobileNumber = null,
            string? photoUrl = null);
        Task<bool> DeleteUserAsync(string id);
        Task<bool> UpdateUserAsync(User user);
        Task SaveChangesAsync(bool force = true);
    }
}
