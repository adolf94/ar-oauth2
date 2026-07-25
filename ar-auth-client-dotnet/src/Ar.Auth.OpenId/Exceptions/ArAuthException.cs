namespace Ar.Auth.OpenId.Exceptions;

/// <summary>
/// Base exception for ar-auth related errors.
/// </summary>
public class ArAuthException : Exception
{
    public ArAuthException(string message) : base(message) { }
    public ArAuthException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Thrown when token validation fails (signature, expiration, issuer, etc.).
/// </summary>
public class TokenValidationException : ArAuthException
{
    public TokenValidationException(string message) : base(message) { }
    public TokenValidationException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Thrown when the client configuration is invalid or missing required values.
/// </summary>
public class ConfigurationException : ArAuthException
{
    public ConfigurationException(string message) : base(message) { }
    public ConfigurationException(string message, Exception innerException) : base(message, innerException) { }
}
