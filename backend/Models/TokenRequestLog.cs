using System;
using System.ComponentModel.DataAnnotations;

namespace backend.Models
{
    public class TokenRequestLog
    {
        [Key]
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public DateTime DateLogged { get; set; } = DateTime.UtcNow;
        public string GrantType { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
        public string NewCode { get; set; } = string.Empty;
        public bool IsError { get; set; }
        public string Reason { get; set; } = string.Empty;
    }
}
