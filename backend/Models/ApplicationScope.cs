using System;

namespace backend.Models
{
    public class ApplicationScope
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string ClientId { get; set; } = string.Empty; // Owner of the scope
        public string Name { get; set; } = string.Empty;     // e.g., "products:read" (not including the app prefix/namespace)
        public string? Description { get; set; }
        public bool IsAdminApproved { get; set; } = false;
        public bool? IsClientOnly { get; set; } = false;
        public DateTime? CreatedAt { get; set; } = DateTime.UtcNow;

        // Fully qualified scope might look like: "api://[clientId]/[name]"
        public string FullScopeName => $"api://{ClientId}/{Name}";
    }
}
