using System.Security.Claims;
using System.Threading.Tasks;
using backend.Models;

namespace backend.Services
{
    public interface ITokenService
    {
        Task<(string Token, string Scopes)> GenerateAccessToken(User user, Client client, string scopes, string? sid = null);
        Task<(string Token, string Scopes)> GenerateClientAccessToken(Client client, string requestedScopes);
        ClaimsPrincipal? ValidateAccessToken(string jwt, string? audience = null);
        Task<string> GenerateRefreshTokenAsync(string userId, string clientId, string scopes, string? sid = null);
        Task<Token?> ValidateRefreshTokenAsync(string tokenValue, string clientId);
        Task<string> RotateRefreshTokenAsync(Token oldToken, string? sid = null);
        string GenerateIdToken(User user, Client client, string nonce = "", string? sid = null);
        Task<bool> IsScopeAuthorizedAsync(User user, Client client, string scope);

        // ── Session Token (Internal ar-auth session) ──
        string GenerateSessionToken(User user);
        ClaimsPrincipal? ValidateSessionToken(string token);
    }
}
