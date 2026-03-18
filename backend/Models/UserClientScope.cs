using System;

namespace backend.Models
{
    public class UserClientScope
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string UserId { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string Scope { get; set; } = string.Empty;
    }
}
