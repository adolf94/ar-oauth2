using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace backend.Services
{
    public class ClientService
    {
        private readonly AppDbContext _dbContext;

        public ClientService(AppDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<Client?> GetByClientIdAsync(string clientId)
        {
            return await _dbContext.Clients.Include(c => c.ClientSecrets).FirstOrDefaultAsync(c => c.ClientId == clientId);
        }

        public async Task<List<Client>> GetAllClientsAsync()
        {
            return await _dbContext.Clients.Include(c => c.ClientSecrets).ToListAsync();
        }

        public async Task<(Client Client, string PlainSecret)> CreateClientAsync(string clientId, List<string> redirectUris, List<string> allowedScopes)
        {
            var plainSecret = GenerateSecret(32);
            var newClient = new Client
            {
                ClientId = clientId,
                RedirectUris = redirectUris,
                AllowedScopes = allowedScopes
            };

            newClient.ClientSecrets.Add(new ClientSecret
            {
                HashedSecret = BCrypt.Net.BCrypt.HashPassword(plainSecret),
                Description = "Initial Secret"
            });

            _dbContext.Clients.Add(newClient);
            await _dbContext.SaveChangesAsync();
            return (newClient, plainSecret);
        }

        public async Task<string> AddSecretAsync(Guid id, string description)
        {
            var client = await _dbContext.Clients.FindAsync(id);
            if (client == null) throw new Exception("Client not found");

            var plainSecret = GenerateSecret(32);
            client.ClientSecrets.Add(new ClientSecret
            {
                HashedSecret = BCrypt.Net.BCrypt.HashPassword(plainSecret),
                Description = description
            });

            await _dbContext.SaveChangesAsync();
            return plainSecret;
        }

        public bool VerifyClientSecret(string plainSecret, List<ClientSecret> secrets)
        {
            if (secrets == null || !secrets.Any()) return false;
            return secrets.Any(s => BCrypt.Net.BCrypt.Verify(plainSecret, s.HashedSecret));
        }

        public string GenerateSecret(int length = 32)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var result = new StringBuilder(length);
            using var rng = RandomNumberGenerator.Create();
            byte[] uintBuffer = new byte[sizeof(uint)];

            while (result.Length < length)
            {
                rng.GetBytes(uintBuffer);
                uint num = BitConverter.ToUInt32(uintBuffer, 0);
                result.Append(chars[(int)(num % (uint)chars.Length)]);
            }

            return result.ToString();
        }
        
        public async Task<bool> UpdateClientAsync(Guid id, List<string> redirectUris, List<string> allowedScopes)
        {
            var client = await _dbContext.Clients.FindAsync(id);
            if (client == null) return false;

            client.RedirectUris = redirectUris;
            client.AllowedScopes = allowedScopes;

            await _dbContext.SaveChangesAsync();
            return true;
        }

        public async Task<bool> DeleteClientAsync(Guid id)
        {
            var client = await _dbContext.Clients.FindAsync(id);
            if (client == null) return false;

            _dbContext.Clients.Remove(client);
            await _dbContext.SaveChangesAsync();
            return true;
        }

        public async Task<bool> DeleteSecretAsync(Guid clientId, string secretId)
        {
            var client = await _dbContext.Clients.Include(c => c.ClientSecrets).FirstOrDefaultAsync(c => c.Id == clientId);
            if (client == null) return false;

            var secret = client.ClientSecrets.FirstOrDefault(s => s.Id == secretId);
            if (secret == null) return false;

            client.ClientSecrets.Remove(secret);
            await _dbContext.SaveChangesAsync();
            return true;
        }
    }
}
