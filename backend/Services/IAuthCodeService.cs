using System.Threading.Tasks;
using backend.Models;

namespace backend.Services
{
    public interface IAuthCodeService
    {
        Task<AuthCode> CreateAuthCodeAsync(string clientId, string userId, string redirectUri, string codeChallenge, string codeChallengeMethod, string scopes);
        Task<AuthCode?> ValidateAuthCodeAsync(string code, string clientId, string redirectUri, string codeVerifier);
    }
}
