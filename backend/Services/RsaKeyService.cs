using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using System.Threading.Tasks;

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
        private readonly Configuration.AppConfig _appConfig;

        public RsaKeyService(Configuration.AppConfig appConfig)
        {
            _appConfig = appConfig;
            _primaryKeyId = appConfig.Jwt.RsaPrimaryKeyId?.ToLower();

            // 1. Initial Load from Environment Variables (Legacy/Dev)
            LoadFromEnvironment();

            // 2. Initialize Key Vault if configured
            if (!string.IsNullOrEmpty(appConfig.Jwt.KeyVaultUri))
            {
                // Note: In a real production app, you might call this periodically 
                // or use a background sync to refresh keys without restarting.
                InitializeFromKeyVaultAsync().GetAwaiter().GetResult();
            }

            // 3. Development Fallback
            if (!_keys.Any())
            {
                var devRsa = RSA.Create(2048);
                _keys.Add(new RsaKeyInfo { KeyId = "dev-key-1", Rsa = devRsa });
            }
        }

        private void LoadFromEnvironment()
        {
            var envVars = Environment.GetEnvironmentVariables();
            foreach (string key in envVars.Keys)
            {
                if (key.StartsWith("RS256_KEY_") || key.StartsWith("AppConfig__Jwt__RSAKey"))
                {
                    var pem = envVars[key]?.ToString();
                    if (!string.IsNullOrEmpty(pem))
                    {
                        var rsa = RSA.Create();
                        rsa.ImportFromPem(pem);
                        var cleanId = key.Replace("AppConfig__Jwt__", "").ToLower();
                        _keys.Add(new RsaKeyInfo { KeyId = cleanId, Rsa = rsa });
                    }
                }
            }
        }

        private async Task InitializeFromKeyVaultAsync()
        {
            try
            {
                var client = new KeyClient(new Uri(_appConfig.Jwt.KeyVaultUri!), new DefaultAzureCredential());
                
                // Fetch all versions of the "ar-auth-signing-key"
                // This allows the system to validate tokens signed with older keys during rotation.
                await foreach (var keyProps in client.GetPropertiesOfKeyVersionsAsync("ar-auth-signing-key"))
                {
                    if (keyProps.Enabled == true)
                    {
                        var keyVersion = await client.GetKeyAsync("ar-auth-signing-key", keyProps.Version);
                        var rsa = keyVersion.Value.Key.ToRSA();
                        _keys.Add(new RsaKeyInfo 
                        { 
                            KeyId = keyProps.Version, // Use the version ID as the KeyId
                            Rsa = rsa 
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Failed to fetch keys from Key Vault: {ex.Message}");
            }
        }

        public RsaSecurityKey GetSigningKey()
        {
            // Use the specified primary key, or the latest one loaded
            var keyInfo = _keys.FirstOrDefault(k => k.KeyId == _primaryKeyId) ?? _keys.LastOrDefault();
            if (keyInfo == null) throw new InvalidOperationException("No RSA keys available.");
            
            return new RsaSecurityKey(keyInfo.Rsa) { KeyId = keyInfo.KeyId };
        }

        public IEnumerable<RsaSecurityKey> GetValidationKeys()
        {
            return _keys.Select(k => {
                // Ensure we only export public parameters for validation keys
                var parameters = k.Rsa.ExportParameters(false);
                var publicRsa = RSA.Create();
                publicRsa.ImportParameters(parameters);
                return new RsaSecurityKey(publicRsa) { KeyId = k.KeyId };
            });
        }

        public IEnumerable<RsaKeyInfo> GetAllKeys() => _keys;
    }
}
