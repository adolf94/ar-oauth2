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
        private readonly IDbHelper _dbHelper;

        public UserService(AppDbContext dbContext, IDbHelper dbHelper)
        {
            _dbContext = dbContext;
            _dbHelper = dbHelper;
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
            string? externalMobileNumber = null,
            string? photoUrl = null)
        {
            var newUser = new User
            {
                Email = email,
                MobileNumber = mobileNumber,
                Roles = roles,
                Name = name ?? string.Empty,
                Picture = photoUrl
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
                    MobileNumber = externalMobileNumber,
                    PhotoUrl = photoUrl
                });
            }

            _dbContext.Users.Add(newUser);
            await _dbHelper.SaveChangesAsync();
            return newUser;
        }

        public async Task<bool> DeleteUserAsync(string id)
        {
            var user = await _dbContext.Users.FindAsync(id);
            if (user == null) return false;

            _dbContext.Users.Remove(user);
            await _dbHelper.SaveChangesAsync();
            return true;
        }

        public async Task<bool> UpdateUserAsync(User user)
        {
            if (user == null) return false;

            await _dbHelper.SaveChangesAsync(force: false);
            return true;
        }

        public async Task SaveChangesAsync(bool force = true)
        {
            await _dbHelper.SaveChangesAsync(force);
        }

        public async Task LinkTelegramIdentityAsync(User user, string telegramId, string? sub = null, string? name = null, string? email = null, string? phone = null, string? photoUrl = null)
        {
            // 1. Check if this Telegram ID is already linked to ANOTHER user
            var existingUser = await GetByExternalIdentityAsync("telegram", telegramId);
            if (existingUser != null && existingUser.Id != user.Id)
            {
                // Override and Warn: Unlink from the old user
                existingUser.RemoveIdentity("telegram");
                // Note: We don't SaveChanges here yet, we'll do it when the main user is updated or via DbHelper batch
            }

            // 2. Link to the target user
            user.SyncIdentity("telegram", telegramId, sub, name, email, phone, photoUrl);
        }
    }
}
