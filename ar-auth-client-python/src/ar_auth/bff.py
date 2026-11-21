"""Same-domain BFF integration for FastAPI (docs/python-bff-implementation-plan.md).

The API processes the OIDC login callback and issues an app-local HttpOnly session
cookie — no access, refresh, or ID token ever reaches JavaScript (design:
docs/cookie-auth-plan.md §3, §5). AuthLib owns state/PKCE/correlation (T0.2);
itsdangerous-signed tickets hold validated claims only.

Requires the ``[fastapi]`` extra (``authlib``, ``httpx``, ``itsdangerous``,
``cryptography``).
"""

from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Optional
from urllib.parse import urlsplit

from authlib.integrations.base_client import OAuthError
from authlib.integrations.starlette_client import OAuth
from authlib.oauth2 import OAuth2Error
from itsdangerous import URLSafeTimedSerializer
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from .exceptions import ConfigurationError

__all__ = ["BffCsrfMode", "BffOptions", "ArAuthBff", "add_ar_auth_bff"]

SESSION_COOKIE_SUFFIX = "ar_bff_session"
STATE_COOKIE_SUFFIX = "ar_bff_state"  # correlation, session-backed via SessionMiddleware
RETURN_URL_SESSION_KEY = "_ar_bff_return_url"


class BffCsrfMode(str, Enum):
    """CSRF enforcement mode (Stage 4). Default: signed double-submit, on."""

    SIGNED_DOUBLE_SUBMIT = "signed-double-submit"
    OFF = "off"


def _derive_key(secret: bytes, purpose: str) -> bytes:
    """Per-purpose subkey from the configured secret (T0.3, no DataProtection)."""
    return hashlib.sha256(secret + b"|ar-bff|" + purpose.encode()).digest()


def _normalize_authority(authority: str) -> str:
    if not authority.startswith(("http://", "https://")):
        authority = f"https://{authority}"
    return authority.rstrip("/")


def _cookie_prefix(cookie_path: str) -> str:
    """Cookie-name prefix derived from the effective cookie path (T0.2 rule).

    "/application1/api/" -> "application1-api.", "/" -> "".
    """
    segments = [s for s in cookie_path.split("/") if s]
    return "-".join(segments) + "." if segments else ""


@dataclass
class BffOptions:
    """Configuration for the ar-auth BFF (Stage 2 subset of the §3.8 API shape)."""

    client_id: str
    secret: "str | bytes"
    authority: str = "auth.adolfrey.com/api"
    login_path: str = "/auth/login"
    callback_path: str = "/auth/callback"
    logout_path: str = "/auth/logout"
    public_base_url: Optional[str] = None
    cookie_path: Optional[str] = None
    cookie_name_prefix: Optional[str] = None
    session_expiry: timedelta = timedelta(hours=8)
    correlation_ttl: timedelta = timedelta(minutes=10)
    csrf: BffCsrfMode = BffCsrfMode.SIGNED_DOUBLE_SUBMIT
    scope: str = "openid profile"
    secure_cookies: Optional[bool] = None

    def __post_init__(self) -> None:
        if not self.client_id:
            raise ConfigurationError("BffOptions.client_id is required")
        if not isinstance(self.secret, (str, bytes)) or not self.secret:
            raise ConfigurationError(
                "BffOptions.secret is required (32+ random bytes; persist and share it "
                "across instances/restarts — there is no default key ring)."
            )

        self.authority = _normalize_authority(self.authority)

        for name in ("login_path", "callback_path", "logout_path"):
            if not getattr(self, name).startswith("/"):
                raise ConfigurationError(f"BffOptions.{name} must start with '/'")
        if self.session_expiry.total_seconds() <= 0:
            raise ConfigurationError("BffOptions.session_expiry must be positive")
        if self.correlation_ttl.total_seconds() <= 0:
            raise ConfigurationError("BffOptions.correlation_ttl must be positive")

        if self.public_base_url:
            parts = urlsplit(self.public_base_url)
            if parts.scheme not in ("http", "https") or not parts.netloc:
                raise ConfigurationError(
                    "BffOptions.public_base_url must be an absolute http(s) URL"
                )

        # Static cookie scoping (options-only, mirrors the .NET rule):
        # explicit cookie_path -> public_base_url path -> "/".
        base_path = urlsplit(self.public_base_url).path if self.public_base_url else ""
        self.cookie_path = (self.cookie_path or base_path or "/").rstrip("/") + "/"

        if self.secure_cookies is None:
            scheme = (
                urlsplit(self.public_base_url).scheme
                if self.public_base_url
                else urlsplit(self.authority).scheme
            )
            self.secure_cookies = scheme == "https"

    @property
    def _secret_bytes(self) -> bytes:
        return self.secret.encode() if isinstance(self.secret, str) else self.secret

    @property
    def session_seconds(self) -> int:
        return int(self.session_expiry.total_seconds())

    @property
    def correlation_seconds(self) -> int:
        return int(self.correlation_ttl.total_seconds())

    @property
    def effective_cookie_prefix(self) -> str:
        if self.cookie_name_prefix is not None:
            return self.cookie_name_prefix
        return _cookie_prefix(self.cookie_path)


class ArAuthBff:
    """The BFF endpoints and session machinery. Security-critical work (state,
    PKCE, id_token validation) is owned by AuthLib + this class; Stage 5 adds
    hooks around it."""

    def __init__(self, options: BffOptions):
        self.options = options
        self.session_cookie_name = f"{options.effective_cookie_prefix}{SESSION_COOKIE_SUFFIX}"
        self.state_cookie_name = f"{options.effective_cookie_prefix}{STATE_COOKIE_SUFFIX}"

        self._session_signer = URLSafeTimedSerializer(
            _derive_key(options._secret_bytes, "session").hex(),
            salt="ar-bff-session",
        )

        self._oauth = OAuth()
        self._oauth.register(
            "arauth",
            client_id=options.client_id,
            server_metadata_url=f"{options.authority}/.well-known/openid-configuration",
            client_kwargs={
                "code_challenge_method": "S256",  # PKCE mandatory (public client)
                "token_endpoint_auth_method": "none",  # no secret
            },
        )
        self._client = self._oauth.arauth

    # ── request-time path resolution (public_base_url → root_path →
    #    X-Forwarded-Prefix → bare host) ─────────────────────────────────────

    def _redirect_base(self, request: Request) -> str:
        if self.options.public_base_url:
            return self.options.public_base_url.rstrip("/")

        scope = request.scope
        scheme = scope["scheme"]
        host, port = scope.get("server") or ("localhost", None)
        hostpart = host if port in (80, 443) or not port else f"{host}:{port}"

        root = scope.get("root_path") or ""
        if not root:
            forwarded = request.headers.get("x-forwarded-prefix", "")
            root = forwarded.rstrip("/")
        return f"{scheme}://{hostpart}{root}"

    def _redirect_uri(self, request: Request) -> str:
        return self._redirect_base(request) + self.options.callback_path

    # ── endpoints (registered by add_ar_auth_bff) ─────────────────────────────

    async def login(self, request: Request) -> Response:
        """GET login_path?returnUrl=/local/path -> 302 to the authorize endpoint."""
        return_url = self._validate_return_url(request.query_params.get("returnUrl"))
        request.session[RETURN_URL_SESSION_KEY] = return_url
        # AuthLib generates state + nonce + PKCE and stores them in the (scoped,
        # short-TTL, signed) session cookie.
        return await self._client.authorize_redirect(
            request, self._redirect_uri(request), scope=self.options.scope
        )

    async def callback(self, request: Request) -> Response:
        """GET callback_path?code=…&state=… -> validates, issues the app session.

        Unknown/consumed code, state mismatch, or a provider error restart the
        login flow gracefully — never a 500 (the .NET §10.B idempotency rule).
        """
        try:
            token = await self._client.authorize_access_token(request)
        except (OAuthError, OAuth2Error):
            return RedirectResponse(self.options.login_path, status_code=302)

        userinfo = token.get("userinfo")  # validated id_token claims (AuthLib)
        if not userinfo:
            return RedirectResponse(self.options.login_path, status_code=302)

        # Claims only: the session cookie never holds access/refresh/ID tokens.
        claims: Dict[str, Any] = dict(userinfo)
        return_url = request.session.pop(RETURN_URL_SESSION_KEY, "/")

        response = RedirectResponse(return_url, status_code=302)
        self._set_session_cookie(response, claims)
        return response

    async def logout(self, request: Request) -> Response:
        """GET logout_path?returnUrl=/local/path -> clears the app-local cookie."""
        return_url = self._validate_return_url(request.query_params.get("returnUrl"))
        response = RedirectResponse(return_url, status_code=302)
        response.delete_cookie(self.session_cookie_name, path=self.options.cookie_path)
        return response

    # ── session ticket ────────────────────────────────────────────────────────

    def authenticate(self, request: Request) -> Optional[Dict[str, Any]]:
        """Validated claims from the app session cookie, or None (Stage 6 wires
        this into the auth precedence)."""
        raw = request.cookies.get(self.session_cookie_name)
        if not raw:
            return None
        try:
            return self._session_signer.loads(raw, max_age=self.options.session_seconds)
        except Exception:  # BadSignature / SignatureExpired / payload issues
            return None

    def _set_session_cookie(self, response: Response, claims: Dict[str, Any]) -> None:
        response.set_cookie(
            self.session_cookie_name,
            self._session_signer.dumps(claims),
            max_age=self.options.session_seconds,
            path=self.options.cookie_path,
            httponly=True,
            samesite="lax",
            secure=self.options.secure_cookies,
        )

    @staticmethod
    def _validate_return_url(url: Optional[str]) -> str:
        """Local-only return URL: no scheme, no protocol-relative, no backslash."""
        if not url or not url.startswith("/") or url.startswith(("//", "/\\")):
            return "/"
        return url

    # ── warmup ────────────────────────────────────────────────────────────────

    async def warmup(self) -> None:
        """Fetch discovery + JWKS so the first login is fully validated.

        Raises at startup (fail-fast) if the authority is unreachable.
        """
        await self._client.load_server_metadata()
        await self._client.fetch_jwk_set()


def add_ar_auth_bff(app: Any, options: BffOptions) -> ArAuthBff:
    """Registers the BFF routes, the scoped correlation session, and the startup
    warmup on a FastAPI app. Call at construction time (before the app starts).

    Returns the :class:`ArAuthBff` instance (Stage 5 hooks live on it).
    """
    bff = ArAuthBff(options)

    # Correlation cookie: AuthLib stores state/nonce/PKCE verifier in the Starlette
    # session; we own that cookie — itsdangerous-signed with a derived key, scoped
    # to the app path, short TTL, HttpOnly + Lax.
    app.add_middleware(
        SessionMiddleware,
        secret_key=_derive_key(options._secret_bytes, "state").hex(),
        session_cookie=bff.state_cookie_name,
        path=options.cookie_path,
        max_age=options.correlation_seconds,
        same_site="lax",
        https_only=options.secure_cookies,
    )

    app.add_api_route(options.login_path, bff.login, methods=["GET"], include_in_schema=False)
    app.add_api_route(options.callback_path, bff.callback, methods=["GET"], include_in_schema=False)
    app.add_api_route(options.logout_path, bff.logout, methods=["GET"], include_in_schema=False)

    # Fail-fast warmup, chained onto the app's lifespan (this Starlette dropped
    # add_event_handler; lifespan composition keeps the app's own lifespan intact).
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def _lifespan_with_warmup(app: Any) -> Any:
        await bff.warmup()
        async with original_lifespan(app):
            yield

    app.router.lifespan_context = _lifespan_with_warmup
    return bff
