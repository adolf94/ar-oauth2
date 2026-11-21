"""In-proc stub OIDC provider for the BFF integration tests (T0.4).

Python port of the .NET ``StubOidcServer``: serves discovery, JWKS, ``/authorize``
(issues a code, echoes state) and ``/token`` (PKCE S256 verification, one-time-use
rotating refresh tokens with burn-on-read). Runs on a random loopback port via
uvicorn so that ``requests`` (ArAuthClient), urllib (PyJWKClient) and httpx (the
BFF) all reach it with real sockets.
"""

import base64
import hashlib
import threading
import time
import uuid
from typing import Dict, Optional
from urllib.parse import parse_qs, quote

import jwt
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse
from starlette.routing import Route


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_int(value: int) -> str:
    return _b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))


class StubOidcServer:
    """Minimal OIDC provider whose signing keys tests can also mint tokens with."""

    CLIENT_ID = "bff-test-client"
    SUB = "user-42"

    def __init__(self) -> None:
        self._rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._codes: Dict[str, Dict[str, str]] = {}
        self._refresh_tokens: Dict[str, str] = {}  # token -> nonce
        self._lock = threading.Lock()
        self._refresh_grant_count = 0
        self.authority = ""
        self._server: Optional[uvicorn.Server] = None
        self._thread: Optional[threading.Thread] = None
        self.app = Starlette(
            routes=[
                Route("/.well-known/openid-configuration", self._discovery, methods=["GET"]),
                Route("/jwks", self._jwks, methods=["GET"]),
                Route("/authorize", self._authorize, methods=["GET"]),
                Route("/token", self._token, methods=["POST"]),
            ]
        )

    # ── lifecycle ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Binds a random loopback port and starts serving in a daemon thread."""
        config = uvicorn.Config(self.app, host="127.0.0.1", port=0, log_level="warning", access_log=False)
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self._server.started and self._server.servers:
                port = self._server.servers[0].sockets[0].getsockname()[1]
                self.authority = f"http://127.0.0.1:{port}"
                return
            time.sleep(0.05)
        raise RuntimeError("stub OIDC server failed to start")

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=10)

    # ── test helpers ────────────────────────────────────────────────────────

    @property
    def refresh_grant_count(self) -> int:
        """Number of refresh_token grants served (attempts, successful or not)."""
        return self._refresh_grant_count

    def revoke_all_refresh_tokens(self) -> None:
        """Simulates server-side revocation: every issued refresh token dies."""
        with self._lock:
            self._refresh_tokens.clear()

    def create_access_token(self, sub: str) -> str:
        """A signed access-token JWT (iss=authority, aud=CLIENT_ID) for the given sub."""
        now = int(time.time())
        return self._sign({
            "iss": self.authority,
            "aud": self.CLIENT_ID,
            "sub": sub,
            "iat": now,
            "exp": now + 600,
        })

    def create_session_token(self, sub: str) -> str:
        """A signed ar-auth session-token JWT (iss=aud=authority, type=session).

        Mimics the auth server's shared-Domain session cookie contents, for the
        legacy session-cookie fallback.
        """
        now = int(time.time())
        return self._sign({
            "iss": self.authority,
            "aud": self.authority,  # session JWTs: audience = issuer
            "sub": sub,
            "type": "session",
            "iat": now,
            "exp": now + 600,
        })

    def _create_id_token(self, client_id: str, nonce: str) -> str:
        now = int(time.time())
        return self._sign({
            "iss": self.authority,
            "aud": client_id,
            "sub": self.SUB,
            "email": "user@example.com",
            "name": "Test User",
            "nonce": nonce,
            "iat": now,
            "exp": now + 600,
        })

    def _sign(self, claims: Dict[str, object]) -> str:
        return jwt.encode(claims, self._rsa, algorithm="RS256", headers={"kid": "stub-key"})

    # ── endpoints ────────────────────────────────────────────────────────────

    async def _discovery(self, request: Request) -> JSONResponse:
        base = self.authority
        return JSONResponse({
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "jwks_uri": f"{base}/jwks",
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["openid", "profile"],
            "token_endpoint_auth_methods_supported": ["none"],
        })

    async def _jwks(self, request: Request) -> JSONResponse:
        pub = self._rsa.public_key().public_numbers()
        return JSONResponse({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "kid": "stub-key",
                "alg": "RS256",
                "n": _b64url_int(pub.n),
                "e": _b64url_int(pub.e),
            }]
        })

    async def _authorize(self, request: Request):
        q = request.query_params
        redirect_uri = q.get("redirect_uri", "")
        if not redirect_uri:
            return PlainTextResponse("missing redirect_uri", status_code=400)

        # PKCE is mandatory for public clients (the ar-auth server enforces this too).
        challenge = q.get("code_challenge", "")
        if not challenge:
            return PlainTextResponse("missing code_challenge", status_code=400)

        state = q.get("state", "")
        nonce = q.get("nonce", "")
        scope = q.get("scope", "")
        code = "stub-" + uuid.uuid4().hex
        self._codes[code] = {
            "redirect_uri": redirect_uri,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": q.get("code_challenge_method", ""),
            "scope": scope,
        }

        sep = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(
            f"{redirect_uri}{sep}code={quote(code)}&state={quote(state)}&scope={quote(scope)}",
            status_code=302,
        )

    async def _token(self, request: Request):
        # Token requests are always application/x-www-form-urlencoded; parsing the
        # body directly avoids the python-multipart dependency Starlette now wants
        # for request.form().
        body = (await request.body()).decode("utf-8")
        form = {k: v[0] for k, v in parse_qs(body).items()}
        grant = form.get("grant_type", "")

        if grant == "refresh_token":
            # Counts refresh round-trips (attempts), successful or not.
            with self._lock:
                self._refresh_grant_count += 1

            provided = form.get("refresh_token", "")
            client_id = form.get("client_id", "")

            if not provided or client_id != self.CLIENT_ID:
                return JSONResponse(
                    {"error": "invalid_request",
                     "error_description": "refresh_token and client_id are required."},
                    status_code=400,
                )

            # One-time-use rotation exactly like the ar-auth server: burn on read.
            with self._lock:
                nonce = self._refresh_tokens.pop(provided, None)
            if nonce is None:
                return JSONResponse(
                    {"error": "invalid_grant",
                     "error_description": "Refresh token is invalid, expired, or already used."},
                    status_code=400,
                )

            rotated = "stub-refresh-" + uuid.uuid4().hex
            with self._lock:
                self._refresh_tokens[rotated] = nonce

            return JSONResponse({
                "access_token": "stub-access-token-" + uuid.uuid4().hex,
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": self._create_id_token(client_id, nonce),
                "refresh_token": rotated,
                "scope": "openid profile",
            })

        code = form.get("code", "")

        # Unknown or deliberately burned code -> invalid_grant (consumed-code test).
        record = None if code == "burned" else self._codes.get(code)
        if record is None:
            return JSONResponse(
                {"error": "invalid_grant",
                 "error_description": "Authorization code is invalid or expired."},
                status_code=400,
            )

        # Verify PKCE S256 exactly like a real provider. A failed verifier does NOT
        # burn the code (mirrors the .NET stub's behavior).
        if record["code_challenge_method"] == "S256":
            verifier = form.get("code_verifier", "")
            computed = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
            if computed != record["code_challenge"]:
                return JSONResponse(
                    {"error": "invalid_grant",
                     "error_description": "PKCE verification failed."},
                    status_code=400,
                )

        with self._lock:
            self._codes.pop(code, None)  # one-time use
            refresh_token = "stub-refresh-" + uuid.uuid4().hex
            self._refresh_tokens[refresh_token] = record["nonce"]

        return JSONResponse({
            "access_token": "stub-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": self._create_id_token(form.get("client_id", ""), record["nonce"]),
            "refresh_token": refresh_token,
            "scope": record["scope"],
        })
