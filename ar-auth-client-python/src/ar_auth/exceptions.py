class ArAuthError(Exception):
    """Base exception class for all ar-auth errors."""
    pass


class TokenValidationError(ArAuthError):
    """Raised when token validation fails (e.g. invalid signature, expired, etc.)."""
    pass


class ConfigurationError(ArAuthError):
    """Raised when the client is misconfigured (e.g. missing client_id)."""
    pass
