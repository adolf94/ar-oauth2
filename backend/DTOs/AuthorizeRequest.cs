namespace backend.DTOs
{
    public class AuthorizeRequest
    {
        public string client_id { get; set; } = string.Empty;
        public string redirect_uri { get; set; } = string.Empty;
        public string response_type { get; set; } = string.Empty;
        public string state { get; set; } = string.Empty;
        public string code_challenge { get; set; } = string.Empty;
        public string code_challenge_method { get; set; } = string.Empty;
        public string scope { get; set; } = string.Empty;
    }
}
