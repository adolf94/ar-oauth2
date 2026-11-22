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
import hmac
import inspect
import logging
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional
from urllib.parse import urlsplit

import httpx
from authlib.integrations.base_client import OAuthError
from authlib.integrations.starlette_client import OAuth
from authlib.oauth2 import OAuth2Error
from cryptography.fernet import Fernet, InvalidToken
from itsdangerous import URLSafeTimedSerializer
from joserfc import jwt as _jose_jwt
from joserfc.jwk import KeySet as _JoseKeySet
from joserfc.jws import JWSRegistry as _JWSRegistry
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from .client import ArAuthClient
from .exceptions import ConfigurationError
from .session_cookie_guard import SessionCookieGuard

logger = logging.getLogger(__name__)

__all__ = [
    "BffCsrfMode",
    "BffOptions",
    "BffEvents",
    "BffRedirectContext",
    "BffAuthenticatedContext",
    "BffLogoutContext",
    "BffRenewalContext",
    "BffRenewOutcome",
    "ArAuthBff",
    "add_ar_auth_bff",
]

SESSION_COOKIE_SUFFIX = "ar_bff_session"
STATE_COOKIE_SUFFIX = "ar_bff_state"  # correlation, session-backed via SessionMiddleware
REFRESH_COOKIE_SUFFIX = "ar_bff_refresh"  # Fernet-parked refresh token (§3.5)
RETURN_URL_SESSION_KEY = "_ar_bff_return_url"
RENEWED_CLAIMS_SCOPE_KEY = "ar_bff_renewed_claims"
XSRF_COOKIE_SUFFIX = "XSRF-TOKEN"  # deliberately JS-readable — that is the point
CSRF_HEADER = "x-csrf-token"
CSRF_HEADER_ALIAS = "x-xsrf-token"  # Angular-style alias
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


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
    events: Optional["BffEvents"] = None
    # Shared-Domain fallback (Stage 6): when no Bearer header and no app session
    # exist, also accept the auth server's own ``ar_auth_session`` cookie.
    # Opt-in, default off — the legacy shared-Domain variant from Stage 1.
    allow_session_cookie: bool = False
    session_cookie_name: str = "ar_auth_session"
    allowed_cookie_origins: Optional[List[str]] = None
    # Post-login landing (where the browser goes after /auth/callback succeeds),
    # used when the login link carries no returnUrl. Resolution order:
    # returnUrl param → captured same-origin Referer (flag) → post_login_app_path
    # → the app's public base path (never the bare site root — behind a
    # prefix-stripping proxy that sits outside the app's mount). All targets are
    # local-only validated (open-redirect guard).
    post_login_app_path: Optional[str] = None
    use_referrer_as_return_url: bool = False

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
        if self.post_login_app_path is not None and not self.post_login_app_path.startswith("/"):
            raise ConfigurationError("BffOptions.post_login_app_path must start with '/'")
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


class _CsrfTokenService:
    """Signed double-submit CSRF token (§4, layer 3).

    The cookie value is an HMAC-signed random blob: the SPA copies it verbatim
    into the ``X-CSRF-Token`` header, and enforcement requires header == cookie
    AND a valid signature. The signature closes cookie tossing — a sibling
    subdomain can plant a ``Domain=.adolfrey.com`` cookie with an attacker-chosen
    value that the SPA would dutifully echo (double-submit would match!), but it
    cannot produce a valid signature. Stateless: no server-side store.
    """

    def __init__(self, key: bytes) -> None:
        self._key = key

    def _sign(self, raw: bytes) -> str:
        signature = hmac.new(self._key, raw, hashlib.sha256).digest()
        return f"{_b64url(raw)}.{_b64url(signature)}"

    def issue(
        self, response: Response, cookie_name: str, path: str, secure: bool, max_age: int
    ) -> str:
        """Issues a fresh signed XSRF cookie (readable by JS — by design) and
        returns its value. Called at session establishment (callback) and at
        silent renewal."""
        value = self._sign(secrets.token_bytes(32))
        response.set_cookie(
            cookie_name,
            value,
            max_age=max_age,
            path=path,
            httponly=False,  # the SPA must read this one — by design
            samesite="lax",
            secure=secure,
        )
        return value

    def validate(self, header: Optional[str], cookie_value: Optional[str]) -> bool:
        """Double-submit check for an unsafe request: the header must echo the
        cookie exactly, and the echoed value must carry a valid signature."""
        if not header or not cookie_value or header != cookie_value:
            return False
        parts = header.split(".")
        if len(parts) != 2:
            return False
        try:
            raw = base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4))
            signature = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        except Exception:
            return False
        expected = hmac.new(self._key, raw, hashlib.sha256).digest()
        return hmac.compare_digest(signature, expected)


async def _run_hook(delegate: Optional[Callable[..., Any]], context: Any) -> None:
    """Fires a BffEvents delegate — sync and async callbacks both supported."""
    if delegate is None:
        return
    result = delegate(context)
    if inspect.isawaitable(result):
        await result


class BffRedirectContext:
    """Context for redirect hooks: login start (may add authorize parameters) and
    the final post-login redirect."""

    def __init__(self, request: Request, return_url: Optional[str] = None) -> None:
        self.request = request
        # Local return URL the user lands on after the flow completes. The login
        # hook may adjust it (base re-sanitizes); the post-login redirecting hook
        # owns it end-to-end (its result is used verbatim).
        self.return_url = return_url
        # Extra query parameters appended to the /authorize redirect.
        # Only honored by the login-redirect hook.
        self.extra_params: Dict[str, str] = {}


class BffAuthenticatedContext:
    """The code was exchanged and validated, and the session is about to be
    issued. Enrich the claims, adjust the return URL, or :meth:`reject` to abort
    the login without issuing any cookie."""

    def __init__(self, request: Request, claims: Dict[str, Any], return_url: Optional[str]) -> None:
        self.request = request
        # Claims built from the validated id_token. Replace or enrich freely
        # (e.g. claims from a local database) — this is what gets signed into
        # the session cookie.
        self.claims = claims
        # Local return URL, validated root-relative. May be adjusted (base
        # re-sanitizes whatever the hook leaves here).
        self.return_url = return_url
        self._rejected = False
        self.reject_reason: Optional[str] = None

    @property
    def rejected(self) -> bool:
        """True after :meth:`reject` was called — no session will be issued."""
        return self._rejected

    def reject(self, reason: str = "") -> None:
        """Aborts the login: no session or refresh cookie is written; the user
        is redirected to the login path."""
        self._rejected = True
        self.reject_reason = reason or None


class BffLogoutContext:
    """Context for the logout hook: local cookies are cleaned by base regardless."""

    def __init__(
        self,
        request: Request,
        claims: Optional[Dict[str, Any]],
        return_url: Optional[str],
    ) -> None:
        self.request = request
        # Validated claims of the current session, if one was present; None otherwise.
        self.claims = claims
        # Local return URL, validated root-relative. May be adjusted (base
        # re-sanitizes whatever the hook leaves here).
        self.return_url = return_url


@dataclass
class BffRenewalContext:
    """Context for the silent-renewal hook: cookies were re-issued from the
    parked refresh token."""

    request: Request
    # Claims of the freshly re-issued session — enrichment propagates into the
    # fresh session cookie.
    claims: Dict[str, Any]


@dataclass
class BffEvents:
    """Delegate-style wiring for the five BFF hooks (the no-subclass alternative
    to overriding :class:`ArAuthBff`). Sync and async callables both work; see
    :class:`ArAuthBff` for the composition rules."""

    on_login_redirecting: Optional[Callable[[BffRedirectContext], Any]] = field(default=None)
    on_authenticated: Optional[Callable[[BffAuthenticatedContext], Any]] = None
    on_redirecting: Optional[Callable[[BffRedirectContext], Any]] = None
    on_logout: Optional[Callable[[BffLogoutContext], Any]] = None
    on_renewed: Optional[Callable[[BffRenewalContext], Any]] = None


class ArAuthBff:
    """The BFF endpoints and session machinery. Security-critical work (state,
    PKCE, correlation, cookie issuance, CSRF checks) lives in this class and the
    pipeline components and ALWAYS runs — overriding a hook cannot skip it.

    Five hook points (§3.9) run around the pipeline built in Stages 2–4:
    subclass and pass an instance to :func:`add_ar_auth_bff` for typed,
    constructor-injected hooks, or set the matching :class:`BffEvents` delegate
    for the no-class alternative. Both surfaces run at the same points and
    compose: calling ``super()`` in an override fires the delegate of the same
    name; NOT calling it merely opts out of that delegate.
    """

    def __init__(self, options: BffOptions):
        self.options = options
        self.session_cookie_name = f"{options.effective_cookie_prefix}{SESSION_COOKIE_SUFFIX}"
        self.state_cookie_name = f"{options.effective_cookie_prefix}{STATE_COOKIE_SUFFIX}"
        self.refresh_cookie_name = f"{options.effective_cookie_prefix}{REFRESH_COOKIE_SUFFIX}"
        self.xsrf_cookie_name = f"{options.effective_cookie_prefix}{XSRF_COOKIE_SUFFIX}"
        self._csrf = _CsrfTokenService(_derive_key(options._secret_bytes, "csrf"))

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
        # Lazy sync client for the opt-in shared-session fallback (Stage 6):
        # only constructed when a request actually exercises that leg.
        self._arauth_client: Optional[ArAuthClient] = None

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

    def _public_path_prefix(self, request: Request) -> str:
        """Browser-visible path prefix ("" or "/gatekeeper").

        Path duality: redirects must target the PUBLIC path — behind a
        prefix-stripping proxy, an internal "/auth/login" Location resolves
        outside the app's mount (404 / the proxy's catch-all site). Same
        resolution rule as _redirect_base: public_base_url path, else
        root_path, else X-Forwarded-Prefix.
        """
        if self.options.public_base_url:
            return urlsplit(self.options.public_base_url).path.rstrip("/")
        root = request.scope.get("root_path") or ""
        if not root:
            root = request.headers.get("x-forwarded-prefix", "")
        return root.rstrip("/")

    def _restart_redirect(self, request: Request) -> RedirectResponse:
        """Graceful login-flow restart: 302 to the PUBLIC login path."""
        prefix = self._public_path_prefix(request)
        return RedirectResponse(f"{prefix}{self.options.login_path}", status_code=302)

    # ── post-login landing ────────────────────────────────────────────────────

    def _same_origin_referer_path(self, request: Request) -> Optional[str]:
        """Local path (+query) of the login request's Referer when it is
        same-origin. Cross-site referrers are ignored — an attacker page
        linking to the login route must not gain a post-login bounce
        (open-redirect guard).
        """
        referer = request.headers.get("referer")
        if not referer:
            return None
        ref_origin = SessionCookieGuard.extract_origin(referer)
        # _redirect_base is the request's browser-visible origin (public_base_url
        # → root_path/X-Forwarded-Prefix → bare host) — comparing against the
        # raw request URL would never match behind a proxy.
        my_origin = SessionCookieGuard.extract_origin(self._redirect_base(request))
        if not ref_origin or not my_origin or ref_origin.lower() != my_origin.lower():
            return None
        parts = urlsplit(referer)
        path = parts.path or "/"
        if not path.startswith("/") or path.startswith(("//", "/\\")):
            return None
        return path + (f"?{parts.query}" if parts.query else "")

    def _resolve_default_landing(self, request: Request) -> str:
        """Post-login landing when the login link carried no ``returnUrl``:
        captured same-origin Referer (opt-in flag) → ``post_login_app_path``
        → the app's public base path. Never the bare site root — behind a
        prefix-stripping proxy that sits outside the app's mount.
        """
        if self.options.use_referrer_as_return_url:
            referrer = self._same_origin_referer_path(request)
            if referrer is not None:
                return referrer
        if self.options.post_login_app_path is not None:
            return self._validate_return_url(self.options.post_login_app_path)
        prefix = self._public_path_prefix(request)
        return f"{prefix}/" if prefix else "/"

    # ── endpoints (registered by add_ar_auth_bff) ─────────────────────────────

    async def login(self, request: Request) -> Response:
        """GET login_path?returnUrl=/local/path -> 302 to the authorize endpoint."""
        raw_return_url = request.query_params.get("returnUrl")
        if raw_return_url is not None:
            return_url = self._validate_return_url(raw_return_url)
        else:
            # Post-login landing resolution (options, see _resolve_default_landing).
            return_url = self._resolve_default_landing(request)

        # Login hook: extra authorize parameters + return-URL adjustment
        # (re-sanitized below — hook output never bypasses the open-redirect guard).
        context = BffRedirectContext(request=request, return_url=return_url)
        await self.on_login_redirecting(context)
        return_url = self._validate_return_url(context.return_url)

        request.session[RETURN_URL_SESSION_KEY] = return_url
        # AuthLib generates state + nonce + PKCE and stores them in the (scoped,
        # short-TTL, signed) session cookie.
        return await self._client.authorize_redirect(
            request,
            self._redirect_uri(request),
            scope=self.options.scope,
            **context.extra_params,
        )

    async def callback(self, request: Request) -> Response:
        """GET callback_path?code=…&state=… -> validates, issues the app session.

        Unknown/consumed code, state mismatch, or a provider error restart the
        login flow gracefully — never a 500 (the .NET §10.B idempotency rule).
        """
        try:
            token = await self._client.authorize_access_token(request)
        except (OAuthError, OAuth2Error) as exc:
            # Consumed/expired code, state mismatch, or a provider error.
            # Logged (description only — never codes or tokens): a silent
            # restart is undebuggable from the outside.
            logger.warning(
                "ar-auth BFF: callback failed, restarting login (%s: %s)",
                type(exc).__name__,
                getattr(exc, "description", None) or getattr(exc, "error", ""),
            )
            return self._restart_redirect(request)

        userinfo = token.get("userinfo")  # validated id_token claims (AuthLib)
        if not userinfo:
            logger.warning("ar-auth BFF: callback got no usable id_token claims")
            return self._restart_redirect(request)

        return_url = request.session.pop(RETURN_URL_SESSION_KEY, None) \
            or self._resolve_default_landing(request)

        # Authenticated hook: enrich/replace the claims (this is what gets signed
        # into the session cookie), adjust the return URL (re-sanitized below),
        # or reject() to abort without issuing any cookie.
        auth_context = BffAuthenticatedContext(request, dict(userinfo), return_url)
        await self.on_authenticated(auth_context)
        if auth_context.rejected:
            # No session, no parked refresh, no XSRF — restart the login flow
            # gracefully (mirrors the .NET Reject() path).
            if auth_context.reject_reason:
                logger.warning(
                    "ar-auth BFF: on_authenticated rejected the login (%s)",
                    auth_context.reject_reason,
                )
            return self._restart_redirect(request)

        # Claims only: the session cookie never holds access/refresh/ID tokens.
        claims: Dict[str, Any] = auth_context.claims
        return_url = self._validate_return_url(auth_context.return_url)

        # Last hook of the login flow: the hook owns the landing URL end-to-end —
        # its result is used verbatim (the .NET Stage-5 ReturnUri trap, ported).
        redirect_context = BffRedirectContext(request=request, return_url=return_url)
        await self.on_redirecting(redirect_context)

        response = RedirectResponse(redirect_context.return_url or "/", status_code=302)
        self._set_session_cookie(response, claims)
        refresh_token = token.get("refresh_token")
        if refresh_token:
            # Park the refresh token (§3.5); access/ID tokens are dropped outright.
            self._refresh_store.park(response, refresh_token)
        if self.options.csrf is not BffCsrfMode.OFF:
            # Fresh CSRF token alongside the fresh session (§4, layer 3).
            self._csrf.issue(
                response,
                self.xsrf_cookie_name,
                self.options.cookie_path,
                self.options.secure_cookies,
                self.options.session_seconds,
            )
        return response

    async def logout(self, request: Request) -> Response:
        """GET logout_path?returnUrl=/local/path -> clears the app-local cookies."""
        return_url = self._validate_return_url(request.query_params.get("returnUrl"))

        # Logout hook: base clears the cookies and redirects regardless (the hook
        # observes / extends, e.g. audit). Return-URL adjustments re-sanitized.
        context = BffLogoutContext(request, self._authenticate_cookie(request), return_url)
        await self.on_logout(context)
        return_url = self._validate_return_url(context.return_url)

        response = RedirectResponse(return_url, status_code=302)
        response.delete_cookie(self.session_cookie_name, path=self.options.cookie_path)
        self._refresh_store.delete(response)  # the parked refresh goes too
        response.delete_cookie(self.xsrf_cookie_name, path=self.options.cookie_path)
        return response

    # ── extensibility hooks (§3.9) ────────────────────────────────────────────
    # Security-critical work lives in the pipeline components and ALWAYS runs;
    # overriding a hook cannot skip it — NOT calling super() merely opts out of
    # the BffEvents delegate of the same name.

    async def on_login_redirecting(self, context: BffRedirectContext) -> None:
        """Before the 302 to the auth server's /authorize. May add extra
        authorize parameters (``context.extra_params``) or adjust the return URL
        (base re-sanitizes it). Base fires ``BffEvents.on_login_redirecting``."""
        if self.options.events:
            await _run_hook(self.options.events.on_login_redirecting, context)

    async def on_authenticated(self, context: BffAuthenticatedContext) -> None:
        """Code exchanged and id_token validated, before the session is issued.
        May enrich/replace ``context.claims``, adjust the return URL, or
        ``context.reject()`` to abort without issuing any cookie. Base fires
        ``BffEvents.on_authenticated``."""
        if self.options.events:
            await _run_hook(self.options.events.on_authenticated, context)

    async def on_redirecting(self, context: BffRedirectContext) -> None:
        """Last hook of the login flow: refresh + XSRF cookies are about to be
        written and the user redirected. The hook owns the landing URL
        end-to-end — ``context.return_url`` is used verbatim. Base fires
        ``BffEvents.on_redirecting``."""
        if self.options.events:
            await _run_hook(self.options.events.on_redirecting, context)

    async def on_logout(self, context: BffLogoutContext) -> None:
        """Logout: the base pipeline (always runs, overridden or not) clears the
        session and companion cookies and redirects; the hook observes / extends
        (e.g. audit). Base fires ``BffEvents.on_logout``."""
        if self.options.events:
            await _run_hook(self.options.events.on_logout, context)

    async def on_renewed(self, context: BffRenewalContext) -> None:
        """After silent renewal succeeded and the session/parked/XSRF cookies
        were re-issued (§3.5). Base fires ``BffEvents.on_renewed``."""
        if self.options.events:
            await _run_hook(self.options.events.on_renewed, context)

    # ── FastAPI auth dependency (Stage 6 precedence) ──────────────────────────

    async def auth(self, request: Request) -> Dict[str, Any]:
        """FastAPI dependency resolving the caller's claims: Bearer header →
        app session cookie (renewal-triggered; the middleware has already run
        by the time a route dependency executes) → opt-in auth-server
        session-cookie fallback.

        The challenge stays JWT-bearer: anonymous callers get 401 with
        ``WWW-Authenticate: Bearer`` — what the SPA's boot probe expects.
        """
        claims = await self._resolve_claims(request)
        if claims is None:
            raise HTTPException(
                status_code=401,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return claims

    async def _resolve_claims(self, request: Request) -> Optional[Dict[str, Any]]:
        # 1. Bearer header — the cross-domain contract; wins whenever present.
        if "authorization" in request.headers:
            return await self._authenticate_bearer(request)

        # 2. App session (renewal ran upstream). Presence chain, not validation
        #    chain: an expired or garbage app cookie still routes here — while
        #    a refresh token is parked, renewal is strictly better than the
        #    shared auth-server cookie (the .NET Stage 6 finding).
        claims = self.authenticate(request)
        if claims is not None:
            return claims

        # 3. Opt-in auth-server session-cookie fallback (shared-Domain variant).
        #    Only consulted when NO app cookie exists at all — otherwise leg 2
        #    owns the request.
        if (
            self.options.allow_session_cookie
            and not request.cookies.get(self.session_cookie_name)
        ):
            return self._authenticate_shared_session(request)

        return None

    async def _authenticate_bearer(self, request: Request) -> Optional[Dict[str, Any]]:
        """Validates the Authorization header as an ar-auth access token (the
        resource-server role) against the authority's warm JWKS. No audience
        enforcement by default — cross-domain tokens carry API-scoped audiences
        (mirrors ``ArAuthClient.verify_token``'s leniency)."""
        parts = request.headers.get("authorization", "").split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
        token = parts[1]

        try:
            metadata = await self._client.load_server_metadata()
            jwks = await self._client.fetch_jwk_set()
            key_set = _JoseKeySet.import_key_set(jwks)
            decoded = _jose_jwt.decode(
                token, key=key_set, registry=_JWSRegistry(algorithms=["RS256"])
            )
        except Exception:  # malformed token, unknown kid, network failure
            return None

        claims = decoded.claims
        if claims.get("iss") != metadata.get("issuer"):
            return None
        exp = claims.get("exp")
        if exp is None or time.time() > float(exp) + 60:  # 60s leeway
            return None
        return claims

    def _authenticate_shared_session(self, request: Request) -> Optional[Dict[str, Any]]:
        """Validates the auth server's session cookie — origin guard first
        (``SessionCookieGuard``), then the ar-auth session JWT (audience =
        issuer, ``type == "session"``). Uses the sync ``ArAuthClient``;
        discovery + JWKS are cached after the first hit."""
        token = request.cookies.get(self.options.session_cookie_name)
        if not token:
            return None

        request_origin = str(request.base_url).rstrip("/")
        if not SessionCookieGuard.is_origin_allowed(
            request.method,
            request.headers.get("origin"),
            request.headers.get("referer"),
            request_origin,
            self.options.allowed_cookie_origins,
        ):
            return None

        try:
            if self._arauth_client is None:
                self._arauth_client = ArAuthClient(authority=self.options.authority)
            return self._arauth_client.verify_session_token(token)
        except Exception:  # TokenValidationError / InvalidTokenError / network
            return None

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
                result = RenewalResult(BffRenewOutcome.RENEWED, latest.claims, latest.refresh_token)
            else:
                result = await self._refresh(parked)
                if result.outcome is BffRenewOutcome.RENEWED:
                    chain.latest = _RenewedSession(
                        result.claims or {}, result.refresh_token or "", time.monotonic()
                    )

            if result.outcome is BffRenewOutcome.RENEWED:
                # Renewal hook: everything is re-issued on the response; claim
                # enrichment propagates into the fresh session cookie. Fires on
                # both the leader and reuse paths (mirrors the .NET IssueAsync).
                await self.on_renewed(BffRenewalContext(request, result.claims or {}))
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
            if self.options.csrf is not BffCsrfMode.OFF:
                # Fresh CSRF token alongside the fresh session. The request that
                # triggered renewal keeps passing on its OLD still-signed token;
                # the SPA picks the new one up on its next read.
                self._csrf.issue(
                    scratch,
                    self.xsrf_cookie_name,
                    self.options.cookie_path,
                    self.options.secure_cookies,
                    self.options.session_seconds,
                )
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
    """Silent renewal + CSRF enforcement (mirrors the .NET middleware):

    - renewal: anonymous request + parked refresh cookie + no Bearer header;
      BFF routes are exempt; a valid session skips renewal entirely.
    - CSRF (§4, layer 3): signed double-submit on unsafe cookie-authenticated
      calls. Bearer requests are exempt (attacker JS cannot forge Authorization
      headers), and so are anonymous requests (401 is the response there —
      403 would mislead the SPA).
    """

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

        # CSRF runs after renewal: a POST that renewed is cookie-authenticated
        # and must pass on its OLD still-signed XSRF token.
        if self._requires_csrf(request) and not self._csrf_valid(request):
            response = Response(status_code=403)
            await response(scope, receive, send_wrapper)  # renewal cookies ride along
            return

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

    def _requires_csrf(self, request: Request) -> bool:
        if request.method in SAFE_METHODS:
            return False
        options = self.bff.options
        if options.csrf is BffCsrfMode.OFF:
            return False
        if request.url.path in (options.login_path, options.callback_path, options.logout_path):
            return False
        if "authorization" in request.headers:
            return False  # Bearer requests are exempt
        # Only the cookie-authenticated path is CSRF-exposed (renewed requests
        # count — authenticate() sees the renewed scope claims first).
        return self.bff.authenticate(request) is not None

    def _csrf_valid(self, request: Request) -> bool:
        cookie_value = request.cookies.get(self.bff.xsrf_cookie_name)
        header = request.headers.get(CSRF_HEADER) or request.headers.get(CSRF_HEADER_ALIAS)
        return self.bff._csrf.validate(header, cookie_value)


def add_ar_auth_bff(
    app: Any,
    options: BffOptions,
    bff: Optional[ArAuthBff] = None,
) -> ArAuthBff:
    """Registers the BFF routes, the scoped correlation session, and the startup
    warmup on a FastAPI app. Call at construction time (before the app starts).

    Pass ``bff`` to use an :class:`ArAuthBff` **subclass** (plain constructor
    injection) instead of the default instance.

    Returns the :class:`ArAuthBff` instance (the Stage 5 hooks live on it).
    """
    if bff is None:
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
