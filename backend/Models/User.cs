using System;
using System.Collections.Generic;

namespace backend.Models
{
    public class User
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Email { get; set; } = string.Empty;
        public string? MobileNumber { get; set; }
        public List<string> Roles { get; set; } = new();
        public Dictionary<string, string> ExternalIdentities { get; set; } = new(); // Mapping for Google `sub` or Passkey `credentialId`
        
        // Llamalabs Automate
        public string? AutomateSecret { get; set; }
        public string? AutomateDeviceName { get; set; }
    }
}
