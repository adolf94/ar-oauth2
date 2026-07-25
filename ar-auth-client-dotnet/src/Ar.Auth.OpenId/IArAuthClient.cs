using System.Security.Claims;
using Ar.Auth.OpenId.Models;

namespace Ar.Auth.OpenId;

/// <summary>
/// Interface for the ArAuth OIDC client.
/// </summary>
public interface IArAuthClient
{
    /// <summary>
    /// Validates a JWT token's RS256 signature, expiration, and issuer.
    /// </summary>
    /// <param name="token">The raw JWT string.</param>
    /// <param name="audience">Optional expected audience (aud) claim.</param>
    /// <returns>The validated ClaimsPrincipal.</returns>
    Task<ClaimsPrincipal> VerifyTokenAsync(string token, string? audience = null);

    /// <summary>
    /// Exchanges an authorization code for tokens.
    /// </summary>
    Task<TokenResponse> ExchangeCodeAsync(string code, string redirectUri, string? codeVerifier = null);

    /// <summary>
    /// Refreshes the access token using a refresh token.
    /// </summary>
    Task<TokenResponse> RefreshTokenAsync(string refreshToken, string? scope = null);

    /// <summary>
    /// Requests an access token using the client_credentials grant (machine-to-machine).
    /// </summary>
    Task<TokenResponse> ClientCredentialsAsync(string? scope = null);
}
