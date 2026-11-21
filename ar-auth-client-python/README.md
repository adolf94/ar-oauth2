# ar-auth-client

A lightweight and robust Python client SDK for `ar-auth` (an OIDC/OAuth 2.0 provider), supporting token verification, code exchange, credentials grants, and framework integrations (FastAPI, Flask, and Azure Functions) — plus a **BFF integration** for same-domain apps that keeps every token out of JavaScript.

See [CHANGELOG.md](CHANGELOG.md) for release history.

## Features

- **Dynamic JWKS Signature Verification**: Automatically retrieves, parses, and caches RSA signature verification keys using `RS256` algorithm.
- **Robust Token Validation**: Validates OIDC claims (expiration, issuer, and signature verification).
- **Default Authority**: Automatically defaults to `auth.adolfrey.com/api` and normalizes authority URLs.
- **Multiple OAuth 2.0 / OIDC Grants**: Supports Authorization Code flow, Refresh Token grant, Client Credentials (machine-to-machine) grant, and Personal Access Token (PAT) exchange.
- **Native Web Framework Integrations**:
  - **FastAPI**: Clean dependency injection checking scopes and roles.
  - **Flask**: Easy-to-use routing decorator context checking.
  - **Azure Functions**: Native decorators that run directly inside Azure Function v2 HTTP triggers.
- **BFF Integration for Same-Domain Apps**: the API processes the OIDC login callback and issues an app-local **HttpOnly session cookie** — no access, refresh, or ID token ever reaches JavaScript (`add_ar_auth_bff`; see below). Requires the `[fastapi]` extra.
- **Optional Session-Cookie Authentication**: on same-site APIs, the auth server's `ar_auth_session` cookie can be accepted as a fallback credential when no Bearer header is present (opt-in; see below).

## Installation

Install using pip:

```bash
pip install ar-auth-client
```

Or install with specific framework extras:

```bash
# For FastAPI support (also required for the BFF integration)
pip install ar-auth-client[fastapi]

# For Flask support
pip install ar-auth-client[flask]

# For Azure Functions support
pip install ar-auth-client[azure]

# Install all dependencies (development)
pip install ar-auth-client[dev]
```

## Basic Usage

### Initialize the Client

The client defaults to `auth.adolfrey.com/api` as the authority. If no scheme is provided, it automatically prepends `https://`.

```python
from ar_auth import ArAuthClient

# Default configuration (authority: https://auth.adolfrey.com/api)
client = ArAuthClient()

# Custom authority & client registration details
client = ArAuthClient(
    authority="auth.adolfrey.com/api",
    client_id="my-client-id",
    client_secret="my-client-secret"
)
```

### Validate and Decode JWT Access / ID Tokens

Validates the token's RS256 signature against dynamically cached keys from the provider's JWKS endpoint, checking issuer (`iss`) and expiration (`exp`).

```python
from ar_auth import ArAuthClient
from ar_auth.exceptions import TokenValidationError

client = ArAuthClient()

try:
    # Decodes and validates signature, expiration, and issuer
    claims = client.verify_token("eyJhbGciOiJSUzI1Ni...")
    print("User authenticated successfully:", claims["sub"])
    print("User Roles:", claims.get("roles", []))
except TokenValidationError as e:
    print("Token verification failed:", str(e))
```

### Authorization Code Exchange

Exchange the OIDC authorization code received on your redirect endpoint for tokens:

```python
tokens = client.exchange_code(
    code="auth_code_from_redirect",
    redirect_uri="https://myapp.com/callback",
    code_verifier="pkce_code_verifier_if_used" # Optional PKCE verifier
)

access_token = tokens["access_token"]
id_token = tokens.get("id_token")
refresh_token = tokens.get("refresh_token")
```

### Refresh Access Token

```python
refreshed_tokens = client.refresh_token(refresh_token=refresh_token)
new_access_token = refreshed_tokens["access_token"]
```

### Client Credentials (M2M)

```python
token_response = client.client_credentials(scope="products:read")
client_access_token = token_response["access_token"]
```

### Personal Access Token (PAT) Exchange

Exchange a personal access token created in the ar-auth dashboard for a short-lived access token.
The requested scopes must be granted by the PAT, and the resulting token carries the PAT owner's identity:

```python
token_response = client.exchange_pat(
    pat_token="arpat_your_personal_access_token",
    scope="products:read",
)
access_token = token_response["access_token"]
```

---

## BFF Integration — Same-Domain Apps (`add_ar_auth_bff`)

**The recommended same-domain integration.** For SPAs served from the same domain as
their API (e.g. the app at `https://apps.adolfrey.com/application1/`, its API at
`https://apps.adolfrey.com/application1/api/`), this SDK implements the
**BFF (Backend-for-Frontend)** pattern: the API processes the OIDC login callback and
issues an app-local HttpOnly session cookie. No token is ever held in JavaScript; the
SPA's entire auth surface is two links and a boot probe. No frontend auth library needed.

Requires the `[fastapi]` extra (`authlib`, `httpx`, `itsdangerous`, `cryptography`).

```python
import secrets
from typing import Any, Dict

from fastapi import Depends, FastAPI

from ar_auth.bff import BffOptions, add_ar_auth_bff

app = FastAPI()
bff = add_ar_auth_bff(app, BffOptions(
    client_id="my-app",               # public client registration (PKCE, no secret)
    secret=secrets.token_urlsafe(48),  # from env/secret store — see deployment box
    # Only needed behind a prefix-stripping reverse proxy, where the public URL
    # differs from what the app sees:
    # public_base_url="https://apps.adolfrey.com/application1/api",
))


@app.get("/me")
async def me(user: Dict[str, Any] = Depends(bff.auth)) -> Any:
    return {"sub": user.get("sub"), "claims": user}


@app.post("/api/things")
async def create_thing(user: Dict[str, Any] = Depends(bff.auth)) -> Any:
    return {"created_for": user.get("sub")}
```

**The flow.** Login is `GET /auth/login?returnUrl=/dashboard`: a 302 to the auth server
(authorization-code flow + PKCE; state, nonce, and the correlation cookie are handled by
the AuthLib machinery). The auth server redirects back to `GET /auth/callback` on the API,
which validates the `id_token`, issues the app session cookie, **parks the refresh token
in its own encrypted cookie**, and 302s to the return URL. `GET /auth/logout` clears every
app-local cookie.

- **Silent renewal**: when the session expires while the parked refresh token is valid,
  the next request transparently re-issues both cookies — single-flight, so concurrent
  tabs cause exactly one refresh round-trip (the ar-auth server rotates refresh tokens
  on each use).
- **CSRF** (default on): `SameSite=Lax` cookies and a signed double-submit token — the
  SPA reads the `XSRF-TOKEN` cookie (readable by JS) and echoes it in the
  `X-CSRF-Token` header on unsafe requests. Sibling-subdomain cookie-tossing fails the
  signature check. `X-XSRF-TOKEN` is accepted as an Angular-style alias; set
  `csrf=BffCsrfMode.OFF` only if you know why.
- **Precedence**: `Depends(bff.auth)` resolves Bearer header → app session cookie →
  (opt-in, see the fallback section below) the auth server's session cookie. An
  `Authorization: Bearer` header always wins over any cookie, so the same API keeps
  serving cross-domain Bearer clients unchanged — and 401 challenges stay
  `WWW-Authenticate: Bearer`.

**Options** (`BffOptions`): `login_path`/`callback_path`/`logout_path` (defaults
`/auth/login|callback|logout`), `public_base_url` (see above), `cookie_path` and
`cookie_name_prefix` (cookie isolation when several apps share one host — the prefix
defaults to the derived cookie path, e.g. `application1.` for `/application1/`),
`session_expiry` (default 8 h, silently renewed while the refresh chain lives),
`scope`, `csrf`, and `secure_cookies`.

**The SPA contract** — the complete frontend auth code, no library:

```html
<a href="/auth/login?returnUrl=/dashboard">Sign in</a>
<a href="/auth/logout?returnUrl=/">Sign out</a>
```

```javascript
// Boot probe: 200 → signed in, 401 → render the signed-out state.
const res = await fetch("/me", { credentials: "same-origin" });

// Unsafe requests echo the readable XSRF-TOKEN cookie in a header.
function xsrfHeader(headers = {}) {
  const token = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/)?.[1];
  return token ? { ...headers, "X-CSRF-Token": token } : headers;
}

await fetch("/api/things", {
  method: "POST",
  credentials: "same-origin",
  headers: xsrfHeader({ "Content-Type": "application/json" }),
  body: JSON.stringify(payload)
});
```

A runnable version of exactly this contract lives in
[`samples/bff_sample`](samples/bff_sample/) — the same SPA works against the .NET
`samples/BffSample` too: the contract is identical across stacks.

**Extensibility**: five hooks around the flow — subclass `ArAuthBff` and register it
with `add_ar_auth_bff(app, options, bff=MyBff(options))`, or set the same hooks as
delegates on `BffOptions(events=BffEvents(...))`: `on_login_redirecting` (extra
authorize parameters), `on_authenticated` (enrich the claims, or `context.reject()`
to abort the login without issuing a session), `on_redirecting`, `on_logout`,
`on_renewed`. Base implementations own every security-critical step — overriding a
hook cannot skip it; not calling `super()` only opts out of the delegate of the same
name.

> **⚠ Deployment — the secret is load-bearing.**
> The session ticket, the parked refresh token, and the CSRF token are all keyed to
> `BffOptions.secret` (SHA-256-labeled subkeys per purpose; the refresh token is
> Fernet-encrypted). There is **no default key ring**: every restart — and every
> instance without the same secret — silently invalidates all sessions. Persist the
> secret (environment variable / secret store) and share it across instances.
> Renewal single-flight is per-process: horizontally scaled deployments need sticky
> sessions or a single BFF instance.

> **Local dev & proxies.** The cookie `Secure` flag is **config-derived** (the scheme
> of `public_base_url`/authority), not per-request: TLS-terminating proxies must set
> `public_base_url` (or `secure_cookies=True`) explicitly, and plain-HTTP local dev
> must pass `secure_cookies=False` — otherwise browsers drop the cookies. For a
> realistic local setup use a local cert (`mkcert`) with
> `uvicorn ... --ssl-certfile ... --ssl-keyfile ...`. Behind a proxy that strips a
> prefix, the redirect URI honors `X-Forwarded-Prefix` (or set `public_base_url`).

---

## Framework Integrations

### 1. FastAPI Integration

Use the `ArAuthBearer` class as a security dependency to protect endpoints, optionally checking for specific roles or scopes.

```python
from typing import Dict, Any
from fastapi import FastAPI, Depends
from ar_auth.fastapi import ArAuthBearer

app = FastAPI()

# Require bearer token with 'admin' role and 'read' scope
admin_auth = ArAuthBearer(
    required_scopes=["read"],
    required_roles=["admin"]
)

@app.get("/admin/dashboard")
def get_dashboard(user_payload: Dict[str, Any] = Depends(admin_auth)):
    return {
        "message": "Welcome to the admin panel!",
        "user_id": user_payload["sub"],
        "roles": user_payload["roles"]
    }
```

`required_scopes` requires **all** listed scopes. Use `any_scopes` when the token only needs **at least one** of the listed scopes:

```python
# Token must have 'read' OR 'write' (at least one)
auth = ArAuthBearer(any_scopes=["read", "write"])
```

### 2. Flask Integration

Protect Flask endpoints using the `@requires_auth` decorator. The decoded token claims are automatically stored in Flask's request context variable `flask.g.ar_auth_user`.

```python
from flask import Flask, jsonify, g
from ar_auth.flask import requires_auth

app = Flask(__name__)

@app.route("/api/profile")
@requires_auth(required_scopes=["profile"])
def get_profile():
    user = g.ar_auth_user
    return jsonify({
        "sub": user["sub"],
        "email": user.get("email"),
        "roles": user.get("roles", [])
    })
```

`@requires_auth` also supports `any_scopes` (at least one of the listed scopes) in addition to `required_scopes` (all of them).

### 3. Azure Functions (API) Integration

Inject authorization validation directly into Azure Functions v2 HTTP Triggers. The decorator automatically validates request headers and passes the decoded OIDC payload as `ar_auth_user`.

```python
import azure.functions as func
from ar_auth.azure import requires_auth_azure

app = func.FunctionApp()

@app.route(route="hello", auth_level=func.AuthLevel.ANONYMOUS)
@requires_auth_azure(required_roles=["developer"])
def hello(req: func.HttpRequest, ar_auth_user: dict) -> func.HttpResponse:
    return func.HttpResponse(
        f"Hello, developer {ar_auth_user['sub']}! You have passed token validation.",
        status_code=200
    )
```

---

## Session-Cookie Fallback (Legacy Shared-Domain Cookie)

> Same-domain apps should prefer the **BFF integration above**: it needs no shared
> `Domain` cookie, gives every app its own path-scoped session, and keeps refresh tokens
> server-side. The fallback below remains supported for the simpler topology where the
> auth server sets a session cookie with `Domain=.adolfrey.com` and sibling APIs honor
> it directly.

By default this library only accepts `Authorization: Bearer` credentials. It can also
accept the auth server's **session cookie** (`ar_auth_session`) as a fallback credential
when no Authorization header is present:

```python
from ar_auth.fastapi import ArAuthBearer

auth = ArAuthBearer(
    authority="auth2.adolfrey.com/api",
    allow_session_cookie=True,                               # opt-in
    allowed_cookie_origins=["https://app.adolfrey.com"],    # optional cross-origin allow-list
)
```

The same options exist on the Flask decorator (`requires_auth(..., allow_session_cookie=True,
allowed_cookie_origins=[...])`) and the Azure Functions decorator
(`requires_auth_azure(...)`) — and on `BffOptions` for the BFF's third precedence leg.
The core validation is also available directly:

```python
claims = client.verify_session_token(token)   # audience = issuer, type == "session"
```

**When this can work at all**: the API must share a registrable domain (site) with the auth
server — e.g. `auth2.adolfrey.com` + `api.adolfrey.com`, with the auth server setting the
cookie via `SessionCookieDomain` (`AppConfig.Jwt.SessionCookieDomain`). Browsers **never**
send the auth server's cookie to an API on a different domain, so for cross-domain APIs
Bearer tokens remain the only option.

Behavior details:

- **Bearer always wins**: a request with an `Authorization` header never consults the cookie.
- **CSRF guard**: the cookie is only honored when the request's `Origin`/`Referer` is
  same-origin (or in `allowed_cookie_origins`). Browsers omit `Origin` on safe methods
  (GET/HEAD), so absence is allowed there; on POST/PUT/DELETE absence is rejected.
- **No privilege escalation**: session JWTs carry `sub`/`email`/`name` only — no roles or
  scopes — so `required_roles`/`required_scopes` still fail cleanly for cookie-authenticated
  callers. The cookie answers "who is this user"; use Bearer tokens for anything privileged.
- The same-site `SameSite=Lax` policy on the cookie is sufficient for subdomain API calls;
  cross-site support (`SameSite=None`) is deliberately not offered (unreliable in Safari).

---

## Running Tests

Tests are placed in the `tests/` directory and can be executed via `pytest`:

```bash
uv run --extra dev python -m pytest
```

The suite includes a real-socket stub OIDC provider (RSA JWKS, PKCE S256, rotating
burn-on-read refresh tokens) and an app-under-test on uvicorn — the same harness the
.NET SDK uses, so behavior stays aligned across stacks.

## License

This project is licensed under the MIT License.
