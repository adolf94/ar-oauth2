using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using backend.Models;

namespace backend.Services
{
    public interface ICrossAppTrustService
    {
        Task<List<CrossAppTrust>> GetTrustsByRequestingClientAsync(string clientId);
        Task<CrossAppTrust> CreateTrustAsync(string requestingClientId, string targetClientId, string scopeName);
        Task<bool> DeleteTrustAsync(Guid id);
    }
}
