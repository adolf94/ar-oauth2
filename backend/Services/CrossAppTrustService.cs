using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Services
{
    public class CrossAppTrustService : ICrossAppTrustService
    {
        private readonly AppDbContext _dbContext;

        public CrossAppTrustService(AppDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<List<CrossAppTrust>> GetTrustsByRequestingClientAsync(string clientId)
        {
            return await _dbContext.CrossAppTrusts
                .Where(t => t.RequestingClientId == clientId)
                .ToListAsync();
        }

        public async Task<CrossAppTrust> CreateTrustAsync(string requestingClientId, string targetClientId, string scopeName)
        {
            var existing = await _dbContext.CrossAppTrusts
                .Where(t => t.RequestingClientId == requestingClientId && 
                               t.TargetClientId == targetClientId && 
                               t.ScopeName == scopeName)
                .FirstOrDefaultAsync() != null;
            
            if (existing) throw new Exception("Trust relationship already exists");

            var trust = new CrossAppTrust
            {
                RequestingClientId = requestingClientId,
                TargetClientId = targetClientId,
                ScopeName = scopeName
            };

            _dbContext.CrossAppTrusts.Add(trust);
            await _dbContext.SaveChangesAsync();
            return trust;
        }

        public async Task<bool> DeleteTrustAsync(Guid id)
        {
            var trust = await _dbContext.CrossAppTrusts.FirstOrDefaultAsync(t => t.Id == id);
            if (trust == null) return false;

            _dbContext.CrossAppTrusts.Remove(trust);
            await _dbContext.SaveChangesAsync();
            return true;
        }
    }
}
