using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Services
{
    public class UserService : IUserService
    {
        private readonly AppDbContext _dbContext;

        public UserService(AppDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<List<User>> GetAllUsersAsync()
        {
            return await _dbContext.Users.ToListAsync();
        }

        public async Task<User?> GetByEmailAsync(string email)
        {
            return await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == email);
        }

        public async Task<User?> GetByExternalIdentityAsync(string provider, string providerId)
        {
            return await _dbContext.Users.FirstOrDefaultAsync(u => u.ExternalIdentities.Any(i => i.Provider == provider && i.ProviderId == providerId));
        }

        public async Task<User?> GetByIdAsync(string id)
        {
            return await _dbContext.Users.FindAsync(id);
        }

        public async Task<User> CreateUserAsync(
            string email, 
            string? mobileNumber, 
            List<string> roles, 
            string? externalProvider = null, 
            string? externalId = null, 
            string? name = null,
            string? sub = null,
            string? externalEmail = null,
            string? externalMobileNumber = null)
        {
            var newUser = new User
            {
                Email = email,
                MobileNumber = mobileNumber,
                Roles = roles,
                Name = name ?? string.Empty
            };

            if (!string.IsNullOrEmpty(externalProvider) && !string.IsNullOrEmpty(externalId))
            {
                newUser.ExternalIdentities.Add(new UserIdentity 
                { 
                    Provider = externalProvider, 
                    ProviderId = externalId,
                    Sub = sub,
                    Name = name,
                    Email = externalEmail,
                    MobileNumber = externalMobileNumber
                });
            }

            _dbContext.Users.Add(newUser);
            await _dbContext.SaveChangesAsync();
            return newUser;
        }

        public async Task<bool> DeleteUserAsync(string id)
        {
            var user = await _dbContext.Users.FindAsync(id);
            if (user == null) return false;

            _dbContext.Users.Remove(user);
            await _dbContext.SaveChangesAsync();
            return true;
        }

        public async Task<bool> UpdateUserAsync(string id, string? mobileNumber, List<string> roles, string? name = null)
        {
            var user = await _dbContext.Users.FindAsync(id);
            if (user == null) return false;

            user.MobileNumber = mobileNumber;
            user.Roles = roles;
            
            if (name != null)
            {
                user.Name = name;
            }

            await _dbContext.SaveChangesAsync();
            return true;
        }

        public async Task<bool> UpdateExternalIdentityDetailsAsync(
            string userId, 
            string provider, 
            string providerId,
            string? sub = null,
            string? name = null,
            string? email = null,
            string? mobileNumber = null)
        {
            var user = await _dbContext.Users.FindAsync(userId);
            if (user == null) return false;

            var identity = user.ExternalIdentities.FirstOrDefault(i => i.Provider == provider);
            if (identity == null)
            {
                identity = new UserIdentity { Provider = provider, ProviderId = providerId };
                user.ExternalIdentities.Add(identity);
            }

            // Always update provider ID just in case
            identity.ProviderId = providerId;
            
            // Update additional fields if provided
            if (sub != null) identity.Sub = sub;
            if (name != null) identity.Name = name;
            if (email != null) identity.Email = email;
            if (mobileNumber != null) identity.MobileNumber = mobileNumber;

            // Sync to top-level user properties if they are empty or dummy
            if (name != null && string.IsNullOrEmpty(user.Name)) user.Name = name;
            if (mobileNumber != null && string.IsNullOrEmpty(user.MobileNumber)) user.MobileNumber = mobileNumber;
            
            if (!string.IsNullOrEmpty(email)) 
            {
                if (string.IsNullOrEmpty(user.Email) || user.Email.EndsWith("@telegram.org"))
                {
                    user.Email = email;
                }
            }

            await _dbContext.SaveChangesAsync();
            return true;
        }

        public async Task<bool> LinkExternalIdentityAsync(
            string id, 
            string provider, 
            string providerId, 
            string? sub = null, 
            string? name = null, 
            string? email = null, 
            string? mobileNumber = null)
        {
            return await UpdateExternalIdentityDetailsAsync(id, provider, providerId, sub, name, email, mobileNumber);
        }

    }
}
