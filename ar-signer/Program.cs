using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using CommandLine;
using Microsoft.IdentityModel.Tokens;
using System.Linq;

namespace ArSigner
{
    [Verb("sign", isDefault: true, HelpText = "Create a signed JWT payload")]
    class SignOptions
    {
        [Option('j', "json", Required = false, HelpText = "Path to a JSON file to use as the payload")]
        public string? JsonFile { get; set; }

        [Option('p', "payload", Required = false, HelpText = "Raw JSON payload string")]
        public string? RawPayload { get; set; }

        [Option('s', "sub", HelpText = "Subject claim")]
        public string? Subject { get; set; }

        [Option('e', "email", HelpText = "Email claim")]
        public string? Email { get; set; }

        [Option('n', "name", HelpText = "Name claim")]
        public string? Name { get; set; }

        [Option('a', "aud", HelpText = "Audience claim")]
        public string? Audience { get; set; }

        [Option('i', "iss", HelpText = "Issuer claim", Default = "https://auth.adolfrey.com/api")]
        public string? Issuer { get; set; }

        [Option("exp", HelpText = "Expiration in minutes", Default = 60)]
        public int? ExpirationMinutes { get; set; }

        [Option("days", HelpText = "Expiration in days (overrides --exp if set)")]
        public int? ExpirationDays { get; set; }

        [Option("kv", HelpText = "Key Vault URI", Default = "https://ars-secret.vault.azure.net/")]
        public string KeyVaultUri { get; set; } = "https://ars-secret.vault.azure.net/";

        [Option("secret", HelpText = "Secret name for the RSA PEM key", Default = "ar-auth-sign")]
        public string SecretName { get; set; } = "ar-auth-sign";
    }

    [Verb("verify", HelpText = "Verify a JWT against JWKS")]
    class VerifyOptions
    {
        [Value(0, MetaName = "token", Required = true, HelpText = "JWT token to verify")]
        public string Token { get; set; } = string.Empty;

        [Option("jwks", HelpText = "JWKS URI", Default = "https://auth.adolfrey.com/api/.well-known/jwks.json")]
        public string JwksUri { get; set; } = "https://auth.adolfrey.com/api/.well-known/jwks.json";

        [Option("iss", HelpText = "Expected Issuer", Default = "ar-auth")]
        public string Issuer { get; set; } = "ar-auth";
    }

    class Program
    {
        static async Task Main(string[] args)
        {
            await Parser.Default.ParseArguments<SignOptions, VerifyOptions>(args)
                .MapResult(
                    (SignOptions opts) => RunSign(opts),
                    (VerifyOptions opts) => RunVerify(opts),
                    errs => Task.FromResult(1)
                );
        }

        static async Task RunSign(SignOptions opts)
        {
            try
            {
                Console.WriteLine($"[INFO] Fetching signing key from: {opts.KeyVaultUri} (Secret: {opts.SecretName})");
                var secretClient = new SecretClient(new Uri(opts.KeyVaultUri), new DefaultAzureCredential());
                var secret = await secretClient.GetSecretAsync(opts.SecretName);
                var pem = secret.Value.Value;

                if (string.IsNullOrEmpty(pem))
                {
                    Console.WriteLine("[ERROR] Secret is empty.");
                    return;
                }

                using var rsa = RSA.Create();
                rsa.ImportFromPem(pem);
                var key = new RsaSecurityKey(rsa) { KeyId = secret.Value.Properties.Version };

                var payload = new JwtPayload();
                payload["iss"] = opts.Issuer;
                if (!string.IsNullOrEmpty(opts.Audience)) payload["aud"] = opts.Audience;
                if (!string.IsNullOrEmpty(opts.Subject)) payload["sub"] = opts.Subject;
                if (!string.IsNullOrEmpty(opts.Email)) payload["email"] = opts.Email;
                if (!string.IsNullOrEmpty(opts.Name)) payload["name"] = opts.Name;

                payload["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                payload["jti"] = Guid.NewGuid().ToString();

                // Calculate Expiration
                DateTime? expiresAt = null;
                if (opts.ExpirationDays.HasValue)
                {
                    expiresAt = DateTime.UtcNow.AddDays(opts.ExpirationDays.Value);
                }
                else if (opts.ExpirationMinutes.HasValue)
                {
                    expiresAt = DateTime.UtcNow.AddMinutes(opts.ExpirationMinutes.Value);
                }

                if (expiresAt.HasValue)
                {
                    payload["exp"] = new DateTimeOffset(expiresAt.Value).ToUnixTimeSeconds();
                }

                // Merge JSON if provided (Merging after defaults allows JSON to override iat/exp/etc if desired)
                string? jsonToMerge = null;
                if (!string.IsNullOrEmpty(opts.JsonFile)) 
                {
                    if (!System.IO.File.Exists(opts.JsonFile))
                    {
                        Console.WriteLine($"[ERROR] File not found: {opts.JsonFile}");
                        return;
                    }
                    jsonToMerge = await System.IO.File.ReadAllTextAsync(opts.JsonFile);
                }
                else if (!string.IsNullOrEmpty(opts.RawPayload)) 
                {
                    jsonToMerge = opts.RawPayload;
                }

                if (!string.IsNullOrEmpty(jsonToMerge))
                {
                    try 
                    {
                        var doc = JsonDocument.Parse(jsonToMerge);
                        foreach (var prop in doc.RootElement.EnumerateObject())
                        {
                            payload[prop.Name] = prop.Value.ValueKind switch
                            {
                                JsonValueKind.String => prop.Value.GetString(),
                                JsonValueKind.Number => prop.Value.TryGetInt64(out long l) ? l : prop.Value.GetDouble(),
                                JsonValueKind.True => true,
                                JsonValueKind.False => false,
                                _ => prop.Value.GetRawText()
                            };
                        }
                    }
                    catch (JsonException ex)
                    {
                        Console.WriteLine($"[WARNING] JSON payload merge failed: {ex.Message}");
                    }
                }

                var header = new JwtHeader(new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
                var token = new JwtSecurityToken(header, payload);
                var handler = new JwtSecurityTokenHandler();
                var jwt = handler.WriteToken(token);

                Console.WriteLine("\n--- SIGNED JWT ---");
                Console.WriteLine(jwt);
                Console.WriteLine("-----------------\n");

                if (!string.IsNullOrEmpty(opts.JsonFile))
                {
                    var outputFile = opts.JsonFile + ".txt";
                    await System.IO.File.WriteAllTextAsync(outputFile, jwt);
                    Console.WriteLine($"[SUCCESS] Signed JWT saved to: {outputFile}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Sign failed: {ex.Message}");
                if (ex.InnerException != null) Console.WriteLine($"[INNER] {ex.InnerException.Message}");
            }
        }

        static async Task RunVerify(VerifyOptions opts)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(opts.Token);

                Console.WriteLine("\n--- DECODED PAYLOAD ---");
                Console.WriteLine(JsonSerializer.Serialize(jwtToken.Payload, new JsonSerializerOptions { WriteIndented = true }));
                Console.WriteLine("-----------------------");

                var expValue = jwtToken.Payload.Expiration;
                if (expValue.HasValue)
                {
                    var expDate = DateTimeOffset.FromUnixTimeSeconds(expValue.Value).UtcDateTime;
                    var timeLeft = expDate - DateTime.UtcNow;
                    Console.WriteLine($"[INFO] Token Expires: {expDate:u} (Time left: {timeLeft.TotalHours:F2} hours)");
                    if (timeLeft.TotalSeconds < 0) Console.WriteLine("[WARNING] Token is already EXPIRED.");
                }

                Console.WriteLine($"[INFO] Fetching JWKS from: {opts.JwksUri}");
                using var client = new System.Net.Http.HttpClient();
                var jwksJson = await client.GetStringAsync(opts.JwksUri);
                var jwks = new JsonWebKeySet(jwksJson);

                var validationParams = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = opts.Issuer,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,
                    IssuerSigningKeys = jwks.GetSigningKeys()
                };

                try
                {
                    handler.ValidateToken(opts.Token, validationParams, out _);
                    Console.WriteLine("\n[SUCCESS] Token signature and lifetime are VALID.");
                }
                catch (Exception valEx)
                {
                    Console.WriteLine($"\n[INVALID] Token validation failed: {valEx.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Verify failed: {ex.Message}");
            }
        }
    }
}
