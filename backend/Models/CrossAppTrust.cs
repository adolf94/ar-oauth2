using System;

namespace backend.Models
{
    public class CrossAppTrust
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        
        // The application where the user is logged in (e.g., AppA)
        public string RequestingClientId { get; set; } = string.Empty;
        
        // The application that owns the resource/scope (e.g., AppB)
        public string TargetClientId { get; set; } = string.Empty;
        
        // The specific scope being trusted (e.g., "read:data" or "api://AppB/read:data")
        public string ScopeName { get; set; } = string.Empty;
        
        public bool IsApproved { get; set; } = true;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Helper to check if a full scope matches this trust
        public bool Matches(string fullScope)
        {
            var targetPrefix = $"api://{TargetClientId}/";
            if (fullScope.StartsWith(targetPrefix))
            {
                var name = fullScope.Substring(targetPrefix.Length);
                return name == ScopeName;
            }
            return false;
        }
    }
}
