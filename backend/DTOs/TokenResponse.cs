using System.Text.Json.Serialization;

namespace backend.DTOs
{
    public class TokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = string.Empty;

        [JsonPropertyName("token_type")]
        public string TokenType { get; set; } = "Bearer";

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }

        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; } = string.Empty;

        [JsonPropertyName("id_token")]
        public string? IdToken { get; set; }

        [JsonPropertyName("scope")]
        public string? Scope { get; set; }
    }
}
