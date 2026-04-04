using System;
using System.Collections.Generic;

namespace backend.Models
{
    public class UserIdentity
    {
        public string Provider { get; set; } = string.Empty;
        public string ProviderId { get; set; } = string.Empty;
        public string? Sub { get; set; }
        public string? Name { get; set; }
        public string? MobileNumber { get; set; }
        public string? Email { get; set; }
        public string? PhotoUrl { get; set; }
    }

    public class UserIdentityConverter : Newtonsoft.Json.JsonConverter
    {
        public override bool CanConvert(Type objectType) => objectType == typeof(List<UserIdentity>);

        public override object? ReadJson(Newtonsoft.Json.JsonReader reader, Type objectType, object? existingValue, Newtonsoft.Json.JsonSerializer serializer)
        {
            if (reader.TokenType == Newtonsoft.Json.JsonToken.Null) return new List<UserIdentity>();
            if (reader.TokenType == Newtonsoft.Json.JsonToken.StartArray)
            {
                return serializer.Deserialize<List<UserIdentity>>(reader) ?? new List<UserIdentity>();
            }
            if (reader.TokenType == Newtonsoft.Json.JsonToken.StartObject)
            {
                // Gracefully handle transition from old empty object {} or dictionary format
                var dict = serializer.Deserialize<Dictionary<string, string>>(reader);
                return dict?.Select(kvp => new UserIdentity { Provider = kvp.Key, ProviderId = kvp.Value }).ToList() ?? new List<UserIdentity>();
            }
            return new List<UserIdentity>();
        }

        public override void WriteJson(Newtonsoft.Json.JsonWriter writer, object? value, Newtonsoft.Json.JsonSerializer serializer)
        {
            serializer.Serialize(writer, value);
        }
    }

    public class User
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Email { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string? MobileNumber { get; set; }
        public List<string> Roles { get; set; } = new();
        public string? Picture { get; set; }

        [Newtonsoft.Json.JsonConverter(typeof(UserIdentityConverter))]
        public List<UserIdentity> ExternalIdentities { get; set; } = new(); // Mapping for Google `sub` or Passkey `credentialId`
    }
}
