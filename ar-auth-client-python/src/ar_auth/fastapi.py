from typing import Optional, List, Dict, Any
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jwt.exceptions import InvalidTokenError

from .client import ArAuthClient
from .exceptions import TokenValidationError
from .session_cookie_guard import SessionCookieGuard

# Default name of the auth server's shared-Domain session cookie.
DEFAULT_SESSION_COOKIE_NAME = "ar_auth_session"


class ArAuthBearer(HTTPBearer):
    """FastAPI security dependency for validating ar-auth Bearer tokens."""

    def __init__(
        self,
        authority: str = "auth.adolfrey.com/api",
        audience: Optional[str] = None,
        required_roles: Optional[List[str]] = None,
        required_scopes: Optional[List[str]] = None,
        any_scopes: Optional[List[str]] = None,
        allow_session_cookie: bool = False,
        session_cookie_name: str = DEFAULT_SESSION_COOKIE_NAME,
        allowed_cookie_origins: Optional[List[str]] = None,
        auto_error: bool = True,
    ):
        """Initializes the security dependency.

        Args:
            authority: The base authority URL. Defaults to 'auth.adolfrey.com/api'.
            audience: Expected audience claim (aud). Optional.
            required_roles: Roles required by the endpoint. Optional.
            required_scopes: Scopes required by the endpoint (all of them). Optional.
            any_scopes: Scopes of which the token must have at least one. Optional.
            allow_session_cookie: Also accept the auth server's session cookie
                (``ar_auth_session``) as a fallback credential when no
                Authorization header is present. Opt-in; the Bearer header
                always wins when present. Optional.
            session_cookie_name: Name of the session cookie. Defaults to
                'ar_auth_session'.
            allowed_cookie_origins: Extra origins allowed to use the session
                cookie cross-origin (same-origin is always allowed). Optional.
            auto_error: Whether to automatically raise exceptions on verification errors.
        """
        super().__init__(auto_error=auto_error)
        self.client = ArAuthClient(authority=authority)
        self.audience = audience
        self.required_roles = required_roles or []
        self.required_scopes = required_scopes or []
        self.any_scopes = any_scopes or []
        self.allow_session_cookie = allow_session_cookie
        self.session_cookie_name = session_cookie_name
        self.allowed_cookie_origins = allowed_cookie_origins

    def _authenticate_session_cookie(self, request: Request) -> Optional[Dict[str, Any]]:
        """Validates the auth-server session cookie (fallback credential).

        The origin guard runs first (SessionCookieGuard); the token must be an
        ar-auth session JWT (audience = issuer, type == "session"). Returns None
        for anything less — the caller falls through to the normal 401 path.
        """
        token = request.cookies.get(self.session_cookie_name)
        if not token:
            return None

        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        request_origin = str(request.base_url).rstrip("/")
        if not SessionCookieGuard.is_origin_allowed(
            request.method, origin, referer, request_origin, self.allowed_cookie_origins
        ):
            return None

        try:
            return self.client.verify_session_token(token)
        except (TokenValidationError, InvalidTokenError):
            return None

    async def __call__(self, request: Request) -> Optional[Dict[str, Any]]:
        """Validates the Authorization header and decodes the token.

        Args:
            request: The incoming FastAPI request.

        Returns:
            The decoded JWT payload dictionary if successful (or None if auto_error is False).
        """
        if self.allow_session_cookie and "authorization" not in request.headers:
            claims = self._authenticate_session_cookie(request)
            if claims is not None:
                return claims
            # No or invalid session cookie: the normal 401 path.
            if self.auto_error:
                raise HTTPException(status_code=401, detail="Not authenticated")
            return None

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
            token_scopes = payload.get("scope", "")
            if isinstance(token_scopes, str):
                token_scopes_list = token_scopes.split()
            elif isinstance(token_scopes, list):
                token_scopes_list = token_scopes
            else:
                token_scopes_list = []

            if self.required_scopes:
                for scope in self.required_scopes:
                    if scope not in token_scopes_list:
                        raise HTTPException(
                            status_code=403,
                            detail=f"Missing required scope: {scope}",
                        )

            if self.any_scopes and not any(scope in token_scopes_list for scope in self.any_scopes):
                raise HTTPException(
                    status_code=403,
                    detail=f"Missing required scope: any of {', '.join(self.any_scopes)}",
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
