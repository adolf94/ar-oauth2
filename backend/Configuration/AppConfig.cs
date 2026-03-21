namespace backend.Configuration
{
    public class AppConfig
    {
        // Cosmos DB
        public CosmosConfig Cosmos { get; set; } = new();

        // Google OAuth
        public GoogleConfig Google { get; set; } = new();
        public TelegramConfig Telegram { get; set; } = new();
        // Passwordless.dev
        public PasswordlessConfig Passwordless { get; set; } = new();

        // OIDC / JWT
        public JwtConfig Jwt { get; set; } = new();
    }

    public class CosmosConfig
    {
        public string Endpoint { get; set; } = string.Empty;
        public string? Key { get; set; }
        public string DatabaseName { get; set; } = "ArAuth";
    }

    public class GoogleConfig
    {
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public string RedirectUri { get; set; } = string.Empty;
    }
    public class TelegramConfig
    {
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public string RedirectUri { get; set; } = string.Empty;
    }

    public class PasswordlessConfig
    {
        public string ApiUrl { get; set; } = "https://v4.passwordless.dev";
        public string ApiSecret { get; set; } = string.Empty;
    }

    public class JwtConfig
    {
        public string Issuer { get; set; } = string.Empty;
        public string? RsaPrimaryKeyId { get; set; }
        public string SecretName { get; set; } = string.Empty;
        public string? KeyVaultUri { get; set; }
    }
}
