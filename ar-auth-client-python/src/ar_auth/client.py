import requests
import jwt
from typing import Dict, Any, Optional
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError, InvalidTokenError

from .exceptions import TokenValidationError, ConfigurationError


class ArAuthClient:
    """Client for authenticating with and validating tokens from ar-auth."""

    def __init__(
        self,
        authority: str = "auth.adolfrey.com/api",
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ):
        """Initializes the ar-auth client.

        Args:
            authority: The base authority URL. Defaults to 'auth.adolfrey.com/api'.
                       If no protocol is provided, 'https://' will be prepended.
            client_id: The client identifier registered in ar-auth. Optional.
            client_secret: The client secret registered in ar-auth. Optional.
        """
        # Normalize authority URL
        if not authority.startswith(("http://", "https://")):
            authority = f"https://{authority}"
        self.authority = authority.rstrip("/")

        self.client_id = client_id
        self.client_secret = client_secret

        self._openid_config: Optional[Dict[str, Any]] = None
        self._jwks_client: Optional[jwt.PyJWKClient] = None

    def get_openid_config(self) -> Dict[str, Any]:
        """Fetches and caches the OpenID configuration from the discovery endpoint.

        Returns:
            The OpenID Connect discovery document dictionary.
        """
        if not self._openid_config:
            url = f"{self.authority}/.well-known/openid-configuration"
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                self._openid_config = response.json()
            except Exception as e:
                raise ConfigurationError(
                    f"Failed to fetch OpenID configuration from {url}: {str(e)}"
                ) from e
        return self._openid_config

    @property
    def token_endpoint(self) -> str:
        """The endpoint to request or refresh tokens."""
        try:
            return self.get_openid_config()["token_endpoint"]
        except Exception:
            return f"{self.authority}/token"

    @property
    def userinfo_endpoint(self) -> str:
        """The endpoint to fetch user profile claims."""
        try:
            return self.get_openid_config()["userinfo_endpoint"]
        except Exception:
            return f"{self.authority}/userinfo"

    @property
    def jwks_uri(self) -> str:
        """The endpoint containing the signature verification keys."""
        try:
            return self.get_openid_config()["jwks_uri"]
        except Exception:
            return f"{self.authority}/.well-known/jwks.json"

    def get_jwks_client(self) -> jwt.PyJWKClient:
        """Gets or initializes the PyJWKClient used for signature verification.

        Returns:
            A jwt.PyJWKClient instance pointing to the JWKS endpoint.
        """
        if not self._jwks_client:
            self._jwks_client = jwt.PyJWKClient(self.jwks_uri)
        return self._jwks_client

    def verify_token(self, token: str, audience: Optional[str] = None, leeway: int = 0) -> Dict[str, Any]:
        """Decodes and validates a JWT access token or ID token using RS256 signature verification.

        Args:
            token: The raw JWT string.
            audience: The expected audience (aud) claim. Optional.
            leeway: Expiration check leeway in seconds. Defaults to 0.

        Returns:
            The decoded token claims dictionary.

        Raises:
            TokenValidationError: If signature verification, expiration check, or claim checks fail.
        """
        try:
            jwks_client = self.get_jwks_client()
            signing_key = jwks_client.get_signing_key_from_jwt(token)

            # ar-auth's expected issuer is the normalized authority URL
            expected_issuer = self.authority

            options = {}
            if audience is None:
                options["verify_aud"] = False

            return jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=audience,
                issuer=expected_issuer,
                leeway=leeway,
                options=options,
            )
        except (ExpiredSignatureError, InvalidSignatureError, InvalidTokenError) as e:
            raise TokenValidationError(f"Token validation failed: {str(e)}") from e
        except Exception as e:
            raise TokenValidationError(f"Unexpected token validation error: {str(e)}") from e

    def get_userinfo(self, access_token: str) -> Dict[str, Any]:
        """Fetches user claims from the UserInfo endpoint.

        Args:
            access_token: A valid access token.

        Returns:
            The UserInfo response payload.
        """
        headers = {"Authorization": f"Bearer {access_token}"}
        try:
            response = requests.get(self.userinfo_endpoint, headers=headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise TokenValidationError(f"Failed to retrieve userinfo: {str(e)}") from e

    def exchange_code(self, code: str, redirect_uri: str, code_verifier: Optional[str] = None) -> Dict[str, Any]:
        """Exchanges an authorization code for tokens.

        Args:
            code: The authorization code received from redirect.
            redirect_uri: The redirect URI matching the initial authorization request.
            code_verifier: The PKCE code verifier (if PKCE was used). Optional.

        Returns:
            The OIDC token endpoint response containing access_token, id_token, refresh_token.
        """
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }
        if self.client_id:
            data["client_id"] = self.client_id
        if self.client_secret:
            data["client_secret"] = self.client_secret
        if code_verifier:
            data["code_verifier"] = code_verifier

        try:
            response = requests.post(self.token_endpoint, data=data, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise TokenValidationError(f"Token exchange failed: {str(e)}") from e

    def refresh_token(self, refresh_token: str, scope: Optional[str] = None) -> Dict[str, Any]:
        """Refreshes the access token using a refresh token.

        Args:
            refresh_token: The refresh token string.
            scope: A subset of scopes to request. Optional.

        Returns:
            The OIDC token endpoint response with the new access token.
        """
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        if self.client_id:
            data["client_id"] = self.client_id
        if self.client_secret:
            data["client_secret"] = self.client_secret
        if scope:
            data["scope"] = scope

        try:
            response = requests.post(self.token_endpoint, data=data, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise TokenValidationError(f"Token refresh failed: {str(e)}") from e

    def client_credentials(self, scope: Optional[str] = None) -> Dict[str, Any]:
        """Requests an access token using the client_credentials grant (machine-to-machine).

        Args:
            scope: The scopes to request. Optional.

        Returns:
            The token response.
        """
        if not self.client_id or not self.client_secret:
            raise ConfigurationError("client_id and client_secret are required for client_credentials grant")

        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if scope:
            data["scope"] = scope

        try:
            response = requests.post(self.token_endpoint, data=data, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise TokenValidationError(f"Client credentials request failed: {str(e)}") from e
