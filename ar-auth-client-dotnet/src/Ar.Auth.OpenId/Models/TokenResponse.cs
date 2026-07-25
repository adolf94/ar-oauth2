using System.Text.Json.Serialization;

namespace Ar.Auth.OpenId.Models;

/// <summary>
/// Represents the response from the OIDC token endpoint.
/// </summary>
public class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("id_token")]
    public string? IdToken { get; set; }

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }
}
