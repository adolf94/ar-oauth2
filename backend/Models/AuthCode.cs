using System;

namespace backend.Models
{
    public class AuthCode
    {
        public string Id { get; set; } = Guid.NewGuid().ToString(); // The code itself
        public string ClientId { get; set; } = string.Empty;
        public string RedirectUri { get; set; } = string.Empty;
        public string CodeChallenge { get; set; } = string.Empty;
        public string CodeChallengeMethod { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
        // UserId isn't there yet because the code might be generated *before* login in a pure API sense, 
        // but typically the code is generated *after* the user logs in. Let's add UserId.
        public string UserId { get; set; } = string.Empty;
        public string Scopes { get; set; } = string.Empty;
    }
}
