using System;

namespace backend.Models
{
    public class PersonalAccessToken
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string UserId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string TokenHash { get; set; } = string.Empty; // SHA-256 hash of raw token
        public string Scopes { get; set; } = string.Empty; // Space-separated list of scopes
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? ExpiresAt { get; set; }
        public DateTime? LastUsedAt { get; set; }
    }
}
