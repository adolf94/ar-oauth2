using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;

namespace backend.Services
{
    public interface IRsaKeyService
    {
        RsaSecurityKey GetSigningKey();
        IEnumerable<RsaSecurityKey> GetValidationKeys();
        IEnumerable<RsaKeyInfo> GetAllKeys();
    }
}
