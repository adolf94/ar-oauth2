from typing import Optional, List, Dict, Any
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jwt.exceptions import InvalidTokenError

from .client import ArAuthClient
from .exceptions import TokenValidationError


class ArAuthBearer(HTTPBearer):
    """FastAPI security dependency for validating ar-auth Bearer tokens."""

    def __init__(
        self,
        authority: str = "auth.adolfrey.com/api",
        audience: Optional[str] = None,
        required_roles: Optional[List[str]] = None,
        required_scopes: Optional[List[str]] = None,
        auto_error: bool = True,
    ):
        """Initializes the security dependency.

        Args:
            authority: The base authority URL. Defaults to 'auth.adolfrey.com/api'.
            audience: Expected audience claim (aud). Optional.
            required_roles: Roles required by the endpoint. Optional.
            required_scopes: Scopes required by the endpoint. Optional.
            auto_error: Whether to automatically raise exceptions on verification errors.
        """
        super().__init__(auto_error=auto_error)
        self.client = ArAuthClient(authority=authority)
        self.audience = audience
        self.required_roles = required_roles or []
        self.required_scopes = required_scopes or []

    async def __call__(self, request: Request) -> Optional[Dict[str, Any]]:
        """Validates the Authorization header and decodes the token.

        Args:
            request: The incoming FastAPI request.

        Returns:
            The decoded JWT payload dictionary if successful (or None if auto_error is False).
        """
        credentials: Optional[HTTPAuthorizationCredentials] = await super().__call__(request)
        if not credentials:
            if self.auto_error:
                raise HTTPException(status_code=401, detail="Not authenticated")
            return None

        token = credentials.credentials
        try:
            # Decode and verify signature
            payload = self.client.verify_token(token, audience=self.audience)

            # Check scopes
            if self.required_scopes:
                token_scopes = payload.get("scope", "")
                if isinstance(token_scopes, str):
                    token_scopes_list = token_scopes.split()
                elif isinstance(token_scopes, list):
                    token_scopes_list = token_scopes
                else:
                    token_scopes_list = []

                for scope in self.required_scopes:
                    if scope not in token_scopes_list:
                        raise HTTPException(
                            status_code=403,
                            detail=f"Missing required scope: {scope}",
                        )

            # Check roles
            if self.required_roles:
                token_roles = payload.get("roles", [])
                if not isinstance(token_roles, list):
                    token_roles = [token_roles]

                for role in self.required_roles:
                    if role not in token_roles:
                        raise HTTPException(
                            status_code=403,
                            detail=f"Missing required role: {role}",
                        )

            return payload
        except TokenValidationError as e:
            raise HTTPException(status_code=401, detail=str(e))
        except InvalidTokenError as e:
            raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
