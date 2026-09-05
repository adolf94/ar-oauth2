namespace Ar.Auth.OpenId;

/// <summary>
/// Configuration options for the ArAuth client.
/// </summary>
public class ArAuthOptions
{
    /// <summary>
    /// The base authority URL for the OIDC provider.
    /// Defaults to "https://auth.adolfrey.com/api".
    /// If no scheme is provided, "https://" will be prepended.
    /// </summary>
    public string Authority { get; set; } = "https://auth.adolfrey.com/api";

    /// <summary>
    /// The client identifier registered in ar-auth. Optional.
    /// Only required for token exchange flows (authorization code, client credentials).
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// The client secret registered in ar-auth. Optional.
    /// Only required for confidential client flows (client credentials, code exchange with secret).
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Gets the normalized authority URL (ensures https:// prefix and trims trailing slash).
    /// </summary>
    public string NormalizedAuthority
    {
        get
        {
            var auth = Authority;
            if (!auth.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !auth.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                auth = $"https://{auth}";
            }
            return auth.TrimEnd('/');
        }
    }

    /// <summary>Expected audience (aud) claim. Optional.</summary>
    public string? Audience { get; set; }

    /// <summary>Roles required to access the function. Optional.</summary>
    public string[]? RequiredRoles { get; set; }

    /// <summary>Scopes required to access the function (all of them). Optional.</summary>
    public string[]? RequiredScopes { get; set; }

    /// <summary>Scopes of which the token must have at least one. Optional.</summary>
    public string[]? AnyScopes { get; set; }

    /// <summary>A list of function names that should bypass authentication. Optional.</summary>
    public string[]? ExcludedFunctions { get; set; }
}
