using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Services
{
    public class UserService
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

        public async Task<User?> GetByIdAsync(string id)
        {
            return await _dbContext.Users.FindAsync(id);
        }

        public async Task<User> CreateUserAsync(string email, string? mobileNumber, List<string> roles)
        {
            var newUser = new User
            {
                Email = email,
                MobileNumber = mobileNumber,
                Roles = roles
            };

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
        public async Task<bool> UpdateUserAsync(string id, string? mobileNumber, List<string> roles)
        {
            var user = await _dbContext.Users.FindAsync(id);
            if (user == null) return false;

            user.MobileNumber = mobileNumber;
            user.Roles = roles;

            await _dbContext.SaveChangesAsync();
            return true;
        }
    }
}
