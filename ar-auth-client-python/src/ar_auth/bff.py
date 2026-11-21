"""Same-domain BFF integration for FastAPI (docs/python-bff-implementation-plan.md).

The API processes the OIDC login callback and issues an app-local HttpOnly session
cookie — no access, refresh, or ID token ever reaches JavaScript (design:
docs/cookie-auth-plan.md §3, §5). AuthLib owns state/PKCE/correlation (T0.2);
itsdangerous-signed tickets hold validated claims only.

Requires the ``[fastapi]`` extra (``authlib``, ``httpx``, ``itsdangerous``,
``cryptography``).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Optional
from urllib.parse import urlsplit

import httpx
from authlib.integrations.base_client import OAuthError
from authlib.integrations.starlette_client import OAuth
from authlib.oauth2 import OAuth2Error
from cryptography.fernet import Fernet, InvalidToken
from itsdangerous import URLSafeTimedSerializer
from starlette.datastructures import MutableHeaders
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from .exceptions import ConfigurationError

__all__ = ["BffCsrfMode", "BffOptions", "BffRenewOutcome", "ArAuthBff", "add_ar_auth_bff"]

SESSION_COOKIE_SUFFIX = "ar_bff_session"
STATE_COOKIE_SUFFIX = "ar_bff_state"  # correlation, session-backed via SessionMiddleware
REFRESH_COOKIE_SUFFIX = "ar_bff_refresh"  # Fernet-parked refresh token (§3.5)
RETURN_URL_SESSION_KEY = "_ar_bff_return_url"
RENEWED_CLAIMS_SCOPE_KEY = "ar_bff_renewed_claims"


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
    refresh_cookie_ttl: timedelta = timedelta(days=30)
    renewal_reuse_window: timedelta = timedelta(minutes=2)
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
        if self.refresh_cookie_ttl.total_seconds() <= 0:
            raise ConfigurationError("BffOptions.refresh_cookie_ttl must be positive")
        if self.renewal_reuse_window.total_seconds() <= 0:
            raise ConfigurationError("BffOptions.renewal_reuse_window must be positive")

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
    def refresh_seconds(self) -> int:
        return int(self.refresh_cookie_ttl.total_seconds())

    @property
    def reuse_window_seconds(self) -> float:
        return self.renewal_reuse_window.total_seconds()

    @property
    def effective_cookie_prefix(self) -> str:
        if self.cookie_name_prefix is not None:
            return self.cookie_name_prefix
        return _cookie_prefix(self.cookie_path)


class _RefreshStore:
    """Fernet-encrypted parking for the refresh token (§3.5): HttpOnly cookie,
    separate name from the session cookie, same app-local path. The browser
    holds an opaque blob; only the app's configured secret can reveal the token."""

    def __init__(
        self,
        fernet: Fernet,
        cookie_name: str,
        cookie_path: str,
        secure: bool,
        max_age: int,
    ) -> None:
        self._fernet = fernet
        self.cookie_name = cookie_name
        self._path = cookie_path
        self._secure = secure
        self._max_age = max_age

    def park(self, response: Response, refresh_token: str) -> None:
        response.set_cookie(
            self.cookie_name,
            self._fernet.encrypt(refresh_token.encode()).decode("utf-8"),
            max_age=self._max_age,
            path=self._path,
            httponly=True,
            samesite="lax",
            secure=self._secure,
        )

    def read(self, request: Request) -> Optional[str]:
        raw = request.cookies.get(self.cookie_name)
        if not raw:
            return None
        try:
            return self._fernet.decrypt(raw.encode("utf-8")).decode("utf-8")
        except InvalidToken:
            # Wrong secret or a tampered value — the caller treats it as garbage.
            return None

    def delete(self, response: Response) -> None:
        response.delete_cookie(self.cookie_name, path=self._path)


class BffRenewOutcome(str, Enum):
    """Outcome of a silent-renewal attempt."""

    RENEWED = "renewed"  # session (re-)issued — by this call or a reused concurrent renewal
    REJECTED = "rejected"  # parked refresh definitively rejected — burn the cookie
    UNAVAILABLE = "unavailable"  # transient failure — keep the parked cookie


@dataclass
class RenewalResult:
    outcome: BffRenewOutcome
    claims: Optional[Dict[str, Any]] = None
    refresh_token: Optional[str] = None  # the rotated token (RENEWED only)


@dataclass
class _RenewedSession:
    claims: Dict[str, Any]
    refresh_token: str
    renewed_at: float


class _ChainState:
    """Single-flight gate + latest result for one refresh-token chain."""

    def __init__(self) -> None:
        self.lock: "asyncio.Lock" = asyncio.Lock()
        self.latest: Optional[_RenewedSession] = None


class ArAuthBff:
    """The BFF endpoints and session machinery. Security-critical work (state,
    PKCE, id_token validation) is owned by AuthLib + this class; Stage 5 adds
    hooks around it."""

    def __init__(self, options: BffOptions):
        self.options = options
        self.session_cookie_name = f"{options.effective_cookie_prefix}{SESSION_COOKIE_SUFFIX}"
        self.state_cookie_name = f"{options.effective_cookie_prefix}{STATE_COOKIE_SUFFIX}"
        self.refresh_cookie_name = f"{options.effective_cookie_prefix}{REFRESH_COOKIE_SUFFIX}"

        self._refresh_store = _RefreshStore(
            Fernet(base64.urlsafe_b64encode(_derive_key(options._secret_bytes, "refresh"))),
            self.refresh_cookie_name,
            options.cookie_path,
            options.secure_cookies,
            options.refresh_seconds,
        )
        # Single-flight renewal state, keyed by SHA-256 of the refresh token.
        self._renewal_chains: Dict[str, _ChainState] = {}

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
        refresh_token = token.get("refresh_token")
        if refresh_token:
            # Park the refresh token (§3.5); access/ID tokens are dropped outright.
            self._refresh_store.park(response, refresh_token)
        return response

    async def logout(self, request: Request) -> Response:
        """GET logout_path?returnUrl=/local/path -> clears the app-local cookie."""
        return_url = self._validate_return_url(request.query_params.get("returnUrl"))
        response = RedirectResponse(return_url, status_code=302)
        response.delete_cookie(self.session_cookie_name, path=self.options.cookie_path)
        self._refresh_store.delete(response)  # the parked refresh goes too
        return response

    # ── session ticket ────────────────────────────────────────────────────────

    def authenticate(self, request: Request) -> Optional[Dict[str, Any]]:
        """Validated claims from the renewed-then-parked chain, the app session
        cookie, or None (Stage 6 wires this into the auth precedence)."""
        renewed = request.scope.get(RENEWED_CLAIMS_SCOPE_KEY)
        if renewed is not None:
            return renewed
        return self._authenticate_cookie(request)

    def _authenticate_cookie(self, request: Request) -> Optional[Dict[str, Any]]:
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

    # ── silent renewal (§3.5) ─────────────────────────────────────────────────

    async def try_renew(self, request: Request) -> Optional[RenewalResult]:
        """Attempts to (re-)issue the app session from the parked refresh token.

        ar-auth refresh tokens are one-time-use with rotation: two concurrent
        renewals carrying the same token race, and the loser burns a consumed
        token into a spurious logout. All renewals for one token chain serialize
        on a per-chain gate; waiters that arrive while a refresh is in flight
        reuse its result instead of issuing another /token round-trip.
        """
        parked = self._refresh_store.read(request)
        if not parked:
            return None

        # Lock/cache key — SHA-256 of the token, never the raw value.
        chain = self._renewal_chains.setdefault(
            hashlib.sha256(parked.encode()).hexdigest(), _ChainState()
        )

        async with chain.lock:
            # Single-flight: a concurrent request may have refreshed this exact
            # chain while we queued. Our carried token was consumed by that
            # refresh — reuse its result within the reuse window (2 min default;
            # covers the parallel-401 storm).
            latest = chain.latest
            if (
                latest is not None
                and latest.refresh_token != parked
                and time.monotonic() - latest.renewed_at <= self.options.reuse_window_seconds
            ):
                return RenewalResult(BffRenewOutcome.RENEWED, latest.claims, latest.refresh_token)

            result = await self._refresh(parked)
            if result.outcome is BffRenewOutcome.RENEWED:
                chain.latest = _RenewedSession(
                    result.claims or {}, result.refresh_token or "", time.monotonic()
                )
            return result

    async def _refresh(self, parked: str) -> RenewalResult:
        try:
            # Warm discovery (startup warmup) — this is a cache hit.
            metadata = await self._client.load_server_metadata()
            endpoint = metadata.get("token_endpoint")
            if not endpoint:
                return RenewalResult(BffRenewOutcome.UNAVAILABLE)

            form = {
                "grant_type": "refresh_token",
                "refresh_token": parked,
                "client_id": self.options.client_id,
            }
            async with httpx.AsyncClient(timeout=10) as http:
                response = await http.post(endpoint, data=form)

            # 400/401: the token itself is bad (consumed, expired, revoked,
            # wrong client) — definitive; the parked cookie gets burned.
            if response.status_code in (400, 401):
                return RenewalResult(BffRenewOutcome.REJECTED)
            if response.status_code >= 400:
                return RenewalResult(BffRenewOutcome.UNAVAILABLE)

            try:
                tokens = response.json()
            except ValueError:
                return RenewalResult(BffRenewOutcome.UNAVAILABLE)

            rotated = tokens.get("refresh_token")
            id_token = tokens.get("id_token")
            if not rotated or not id_token:
                return RenewalResult(BffRenewOutcome.UNAVAILABLE)

            # The renewed session mirrors the login principal: claims from a
            # fully validated id_token (signature via warm JWKS, iss, aud, exp).
            # Nonce is deliberately skipped — renewal performs no authorize
            # round-trip, so there is nothing to compare (backend sends nonce ""
            # on the refresh grant by design).
            try:
                userinfo = await self._client.parse_id_token(tokens, nonce=None)
            except Exception:
                return RenewalResult(BffRenewOutcome.REJECTED)
            return RenewalResult(BffRenewOutcome.RENEWED, dict(userinfo), rotated)
        except Exception:
            # Transport/parse failures are transient — never burn the parked
            # token for them.
            return RenewalResult(BffRenewOutcome.UNAVAILABLE)

    def _renewal_cookie_headers(self, result: RenewalResult):
        """Set-Cookie raw headers for the renewal outcome: fresh session +
        re-parked rotated refresh on RENEWED; parked-cookie deletion on
        REJECTED; nothing on UNAVAILABLE (keep the cookie)."""
        scratch = Response()
        if result.outcome is BffRenewOutcome.RENEWED:
            self._set_session_cookie(scratch, result.claims or {})
            self._refresh_store.park(scratch, result.refresh_token or "")
        elif result.outcome is BffRenewOutcome.REJECTED:
            self._refresh_store.delete(scratch)
        # Only the Set-Cookie headers — the scratch response also carries a
        # default content-length that would conflict with the real response.
        return [(n, v) for n, v in scratch.raw_headers if n == b"set-cookie"]

    # ── warmup ────────────────────────────────────────────────────────────────

    async def warmup(self) -> None:
        """Fetch discovery + JWKS so the first login is fully validated.

        Raises at startup (fail-fast) if the authority is unreachable.
        """
        await self._client.load_server_metadata()
        await self._client.fetch_jwk_set()


class _BffRenewalMiddleware:
    """Triggers silent renewal: anonymous request + parked refresh cookie +
    no Bearer header (mirrors the .NET middleware placement). BFF routes are
    exempt; a valid session skips renewal entirely."""

    def __init__(self, app: Any, bff: "ArAuthBff"):
        self.app = app
        self.bff = bff

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":  # pragma: no cover
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        result: Optional[RenewalResult] = None
        if self._should_attempt(request):
            result = await self.bff.try_renew(request)
            if result is not None and result.outcome is BffRenewOutcome.RENEWED and result.claims:
                # The request that triggered renewal is authenticated by it.
                scope[RENEWED_CLAIMS_SCOPE_KEY] = result.claims

        async def send_wrapper(message):
            if message["type"] == "http.response.start" and result is not None:
                headers = MutableHeaders(scope=message)
                for name, value in self.bff._renewal_cookie_headers(result):
                    headers.append(name.decode("latin-1"), value.decode("latin-1"))
            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _should_attempt(self, request: Request) -> bool:
        options = self.bff.options
        if request.url.path in (options.login_path, options.callback_path, options.logout_path):
            return False
        if "authorization" in request.headers:
            return False  # Bearer requests are exempt (cross-domain contract)
        if self.bff._authenticate_cookie(request) is not None:
            return False  # valid session — nothing to renew
        return self.bff._refresh_store.read(request) is not None


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
    # Renewal sits outermost so it can stash renewed claims and append its
    # Set-Cookie headers to every response kind (JSON included, not just
    # redirects — mirrors the .NET middleware).
    app.add_middleware(_BffRenewalMiddleware, bff=bff)

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
