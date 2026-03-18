using System;

namespace backend.Models
{
    public class RoleDefinition
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string ClientId { get; set; } = string.Empty; // The client application that owns this role
        public string Name { get; set; } = string.Empty;     // e.g., 'admin', 'editor'
        public string? Description { get; set; }
        public bool IsActive { get; set; } = true;
    }
}
