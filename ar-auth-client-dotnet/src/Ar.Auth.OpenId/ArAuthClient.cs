using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Ar.Auth.OpenId.Exceptions;
using Ar.Auth.OpenId.Models;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Ar.Auth.OpenId;

/// <summary>
/// Client for authenticating with and validating tokens from ar-auth.
/// </summary>
public class ArAuthClient : IArAuthClient
{
    private readonly ArAuthOptions _options;
    private readonly HttpClient _httpClient;
    private readonly ConfigurationManager<OpenIdConnectConfiguration>? _configManager;
    private readonly JwtSecurityTokenHandler _tokenHandler;

    /// <summary>
    /// Initializes a new instance of ArAuthClient.
    /// </summary>
    /// <param name="options">The configuration options.</param>
    /// <param name="httpClient">Optional HttpClient (useful for DI/testing).</param>
    public ArAuthClient(ArAuthOptions? options = null, HttpClient? httpClient = null)
    {
        _options = options ?? new ArAuthOptions();
        _httpClient = httpClient ?? new HttpClient();
        _tokenHandler = new JwtSecurityTokenHandler();

        var authority = _options.NormalizedAuthority;
        var metadataAddress = $"{authority}/.well-known/openid-configuration";

        _configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            metadataAddress,
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever(_httpClient));
    }

    /// <inheritdoc />
    public async Task<ClaimsPrincipal> VerifyTokenAsync(string token, string? audience = null)
    {
        try
        {
            var config = await _configManager!.GetConfigurationAsync(CancellationToken.None);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = config.SigningKeys,

                ValidateIssuer = true,
                ValidIssuer = _options.NormalizedAuthority,

                ValidateAudience = audience != null,
                ValidAudience = audience,

                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(30),
            };

            var principal = _tokenHandler.ValidateToken(token, validationParameters, out _);
            return principal;
        }
        catch (SecurityTokenExpiredException ex)
        {
            throw new TokenValidationException("Token has expired.", ex);
        }
        catch (SecurityTokenInvalidSignatureException ex)
        {
            throw new TokenValidationException("Token signature is invalid.", ex);
        }
        catch (SecurityTokenException ex)
        {
            throw new TokenValidationException($"Token validation failed: {ex.Message}", ex);
        }
        catch (Exception ex) when (ex is not ArAuthException)
        {
            throw new TokenValidationException($"Unexpected token validation error: {ex.Message}", ex);
        }
    }

    /// <inheritdoc />
    public async Task<TokenResponse> ExchangeCodeAsync(string code, string redirectUri, string? codeVerifier = null)
    {
        var parameters = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
        };

        if (_options.ClientId != null) parameters["client_id"] = _options.ClientId;
        if (_options.ClientSecret != null) parameters["client_secret"] = _options.ClientSecret;
        if (codeVerifier != null) parameters["code_verifier"] = codeVerifier;

        return await PostTokenRequestAsync(parameters);
    }

    /// <inheritdoc />
    public async Task<TokenResponse> RefreshTokenAsync(string refreshToken, string? scope = null)
    {
        var parameters = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
        };

        if (_options.ClientId != null) parameters["client_id"] = _options.ClientId;
        if (_options.ClientSecret != null) parameters["client_secret"] = _options.ClientSecret;
        if (scope != null) parameters["scope"] = scope;

        return await PostTokenRequestAsync(parameters);
    }

    /// <inheritdoc />
    public async Task<TokenResponse> ClientCredentialsAsync(string? scope = null)
    {
        if (string.IsNullOrEmpty(_options.ClientId) || string.IsNullOrEmpty(_options.ClientSecret))
        {
            throw new ConfigurationException(
                "ClientId and ClientSecret are required for the client_credentials grant.");
        }

        var parameters = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = _options.ClientId!,
            ["client_secret"] = _options.ClientSecret!,
        };

        if (scope != null) parameters["scope"] = scope;

        return await PostTokenRequestAsync(parameters);
    }

    private async Task<TokenResponse> PostTokenRequestAsync(Dictionary<string, string> parameters)
    {
        try
        {
            var config = await _configManager!.GetConfigurationAsync(CancellationToken.None);
            var tokenEndpoint = config.TokenEndpoint
                ?? $"{_options.NormalizedAuthority}/token";

            var content = new FormUrlEncodedContent(parameters);
            var response = await _httpClient.PostAsync(tokenEndpoint, content);
            response.EnsureSuccessStatusCode();

            var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();
            return tokenResponse ?? throw new TokenValidationException("Received empty token response.");
        }
        catch (HttpRequestException ex)
        {
            throw new TokenValidationException($"Token request failed: {ex.Message}", ex);
        }
        catch (JsonException ex)
        {
            throw new TokenValidationException($"Failed to parse token response: {ex.Message}", ex);
        }
        catch (Exception ex) when (ex is not ArAuthException)
        {
            throw new TokenValidationException($"Unexpected error during token request: {ex.Message}", ex);
        }
    }
}
