using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace backend.Services
{
    public class RsaKeyInfo
    {
        public string KeyId { get; set; } = string.Empty;
        public RSA Rsa { get; set; } = null!;
    }

    public class RsaKeyService
    {
        private readonly List<RsaKeyInfo> _keys = new();
        private readonly string? _primaryKeyId;

        public RsaKeyService(Configuration.AppConfig appConfig)
        {
            // Support multiple keys from environment for rotation
            // Format: RS256_KEY_1, RS256_KEY_2... 
            
            var envVars = Environment.GetEnvironmentVariables();
            foreach (string key in envVars.Keys)
            {
                // Support both legacy prefix and the new hierarchical AppConfig prefix
                if (key.StartsWith("RS256_KEY_") || key.StartsWith("AppConfig__Jwt__RSAKey"))
                {
                    var pem = envVars[key]?.ToString();
                    if (!string.IsNullOrEmpty(pem))
                    {
                        var rsa = RSA.Create();
                        rsa.ImportFromPem(pem);
                        
                        // Extract a cleaner KeyId (e.g., "rsakey1" instead of "AppConfig__Jwt__RSAKey1")
                        var cleanId = key.Replace("AppConfig__Jwt__", "").ToLower();
                        _keys.Add(new RsaKeyInfo { KeyId = cleanId, Rsa = rsa });
                    }
                }
            }

            _primaryKeyId = appConfig.Jwt.RsaPrimaryKeyId?.ToLower();

            // Development Fallback
            if (!_keys.Any())
            {
                var devRsa = RSA.Create(2048);
                _keys.Add(new RsaKeyInfo { KeyId = "dev-key-1", Rsa = devRsa });
            }
        }

        public RsaSecurityKey GetSigningKey()
        {
            var keyInfo = _keys.FirstOrDefault(k => k.KeyId == _primaryKeyId) ?? _keys.Last();
            return new RsaSecurityKey(keyInfo.Rsa) { KeyId = keyInfo.KeyId };
        }

        public IEnumerable<RsaSecurityKey> GetValidationKeys()
        {
            return _keys.Select(k => {
                var parameters = k.Rsa.ExportParameters(false);
                var publicRsa = RSA.Create();
                publicRsa.ImportParameters(parameters);
                return new RsaSecurityKey(publicRsa) { KeyId = k.KeyId };
            });
        }

        public IEnumerable<RsaKeyInfo> GetAllKeys() => _keys;
    }
}
