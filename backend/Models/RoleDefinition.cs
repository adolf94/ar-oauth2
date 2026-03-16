using System;

namespace backend.Models
{
    public class RoleDefinition
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string AppName { get; set; } = string.Empty; // The client application that owns this role definition (for multi-tenancy)
        public string RoleKey { get; set; } = string.Empty; // The specific role string (e.g., 'admin', 'editor')
        public bool IsActive { get; set; } = true;
    }
}
