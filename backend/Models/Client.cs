using System;
using System.Collections.Generic;

namespace backend.Models
{
    public class Client
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string ClientId { get; set; } = string.Empty;
        public List<ClientSecret> ClientSecrets { get; set; } = new();
        public List<string> RedirectUris { get; set; } = new();
        public List<string> AllowedScopes { get; set; } = new();
    }

    public class ClientSecret
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string HashedSecret { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public string? Description { get; set; }
    }
}
