using System;
using System.ComponentModel.DataAnnotations;

namespace backend.Models
{
    public class LogEntry
    {
        [Key]
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public string Level { get; set; } = "Information";
        public string Source { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public string? Data { get; set; }
    }
}
