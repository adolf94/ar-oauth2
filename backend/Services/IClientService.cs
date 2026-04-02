using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using backend.Models;

namespace backend.Services
{
    public interface IClientService
    {
        Task<Client?> GetByClientIdAsync(string clientId);
        Task<List<Client>> GetAllClientsAsync();
        Task<(Client Client, string PlainSecret)> CreateClientAsync(string clientId, List<string> redirectUris, List<string> allowedScopes);
        Task<Client> CreatePublicClientAsync(string clientId, List<string> redirectUris, List<string> allowedScopes);
        Task<string> AddSecretAsync(Guid id, string description);
        bool VerifyClientSecret(string plainSecret, List<ClientSecret> secrets);
        string GenerateSecret(int length = 32);
        Task<bool> UpdateClientAsync(Guid id, List<string> redirectUris, List<string> allowedScopes);
        Task<bool> DeleteClientAsync(Guid id);
        Task<bool> DeleteSecretAsync(Guid clientId, string secretId);
    }
}
