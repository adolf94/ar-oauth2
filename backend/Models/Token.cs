using System;

namespace backend.Models
{
    public class Token
    {
        public string Id { get; set; } = Guid.NewGuid().ToString(); // Token JTI
        public string Sid { get; set; } = string.Empty; // Session ID linking multiple tokens
        public string UserId { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string Scopes { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }

        /// <summary>
        /// When the session's FIRST refresh token was issued. Carried unchanged
        /// through rotations so the absolute lifetime cap measures the whole
        /// session's age, not just the latest token's. Rows created before this
        /// field existed deserialize as DateTime.MinValue and are stamped with
        /// the current time on their next rotation instead of being rejected.
        /// </summary>
        public DateTime CreatedAt { get; set; }

        /// <summary>
        /// Non-null marks a tombstone: this token has already been rotated and
        /// its row is kept only so a replay can be detected. Presenting a rotated
        /// token revokes the entire session (all tokens sharing its Sid).
        /// </summary>
        public DateTime? RotatedAt { get; set; }
    }
}
