using System;

namespace backend.Models
{
    public class Token
    {
        public string Id { get; set; } = Guid.NewGuid().ToString(); // Token JTI
        public string UserId { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string Scopes { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; } 
    }
}
