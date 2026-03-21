using System;
using System.Security.Cryptography;
using System.Text;
using backend.Models;
using backend.Data;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace backend.Services
{
    public class AuthCodeService
    {
        private readonly AppDbContext _dbContext;

        public AuthCodeService(AppDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<AuthCode> CreateAuthCodeAsync(string clientId, string userId, string redirectUri, string codeChallenge, string codeChallengeMethod, string scopes)
        {
            var authCode = new AuthCode
            {
                ClientId = clientId,
                UserId = userId,
                RedirectUri = redirectUri,
                CodeChallenge = codeChallenge,
                CodeChallengeMethod = codeChallengeMethod,
                Scopes = scopes,
                ExpiresAt = DateTime.UtcNow.AddMinutes(5) // Auth code valid for 5 mins
            };

            _dbContext.AuthCodes.Add(authCode);
            await _dbContext.SaveChangesAsync();

            return authCode;
        }

        public async Task<AuthCode?> ValidateAuthCodeAsync(string code, string clientId, string redirectUri, string codeVerifier)
        {
            var authCode = await _dbContext.AuthCodes.FirstOrDefaultAsync(c => c.Id == code);

            if (authCode == null || authCode.ExpiresAt < DateTime.UtcNow) return null;
            if (authCode.ClientId != clientId || authCode.RedirectUri != redirectUri) return null;

            // Validate PKCE code verifier
            if (string.Equals(authCode.CodeChallengeMethod, "S256", StringComparison.OrdinalIgnoreCase))
            {
                using var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
                var base64UrlHash = Base64UrlEncode(hash);

                if (authCode.CodeChallenge != base64UrlHash) return null;
            }
            else // "plain" (not recommended but allowed by spec)
            {
                if (authCode.CodeChallenge != codeVerifier) return null;
            }

            // Code is valid, remove it so it can't be reused
            try
            {
                _dbContext.AuthCodes.Remove(authCode);
                await _dbContext.SaveChangesAsync();
            }
            catch (DbUpdateException ex) when (ex.InnerException is Microsoft.Azure.Cosmos.CosmosException { StatusCode: System.Net.HttpStatusCode.NotFound })
            {
                // If it's already gone, it was likely processed by a concurrent request.
                // We've already validated the code, so we can continue.
                Console.WriteLine($"[DEBUG] AuthCode {authCode.Id} was already removed by another request.");
            }
            catch (Exception ex)
            {
                // Log other unexpected errors but perhaps don't block the login if the code was already valid
                Console.WriteLine($"[WARNING] Unexpected error removing AuthCode {authCode.Id}: {ex.Message}");
            }

            return authCode;
        }

        private static string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }
    }
}
