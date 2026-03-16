namespace backend.DTOs
{
    public class TokenRequest
    {
        public string grant_type { get; set; } = string.Empty;
        public string client_id { get; set; } = string.Empty;
        public string client_secret { get; set; } = string.Empty;
        public string code { get; set; } = string.Empty;
        public string redirect_uri { get; set; } = string.Empty;
        public string code_verifier { get; set; } = string.Empty;
        public string refresh_token { get; set; } = string.Empty;
    }
}
