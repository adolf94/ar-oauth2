namespace Ar.Auth.OpenId.AspNetCore;

/// <summary>
/// Names of the extra authentication schemes installed when
/// <see cref="ArAuthOptions.AllowSessionCookie"/> is enabled.
/// </summary>
public static class ArAuthPolicyScheme
{
    /// <summary>
    /// Dynamic scheme that forwards to JwtBearer when an Authorization header is present,
    /// and to <see cref="ArAuthSessionHandler.SchemeName"/> otherwise.
    /// </summary>
    public const string SchemeName = "ArAuthSmart";
}
