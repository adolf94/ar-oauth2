# ─────────────────────────────────────────────────────────────────────────────
# ArAuth BFF sample — the same-domain topology from docs/cookie-auth-plan.md §5.
#
# The API processes the OIDC login callback and issues an app-local HttpOnly
# session cookie. No access/refresh/ID token ever reaches JavaScript; the SPA
# (wwwroot/index.html) is two links, a boot probe, and an XSRF header wrapper.
#
# Run it:
#   1) Register a public client on the auth server (PKCE, no secret) whose
#      redirect_uri is  <BFF_PUBLIC_BASE_URL or the bound url> + /auth/callback
#   2) cd ar-auth-client-python
#      AR_AUTH_CLIENT_ID=my-app AR_AUTH_BFF_SECRET="$(python -c \
#          'import secrets; print(secrets.token_urlsafe(48))')" \
#        uv run --extra fastapi uvicorn samples.bff_sample.main:app \
#          --port 8443
#      Optional (only behind a prefix-stripping reverse proxy, where the public
#      URL differs from what the app sees): BFF_PUBLIC_BASE_URL=https://…/app
#   3) open http://127.0.0.1:8443/  → "Sign in" → boot probe shows your sub.
#
# PRODUCTION NOTE: the session ticket and the parked refresh token are keyed to
# BffOptions.secret. There is NO default key ring — every restart (and every
# instance without the same secret) silently invalidates all sessions.
# Persist the secret (env/secret-store) and share it across instances.
# Renewal single-flight is per-process: scale-out needs sticky sessions or a
# single BFF instance.
# ─────────────────────────────────────────────────────────────────────────────

import os
from typing import Any, Dict

from fastapi import Depends, FastAPI
from starlette.staticfiles import StaticFiles

from ar_auth.bff import BffOptions, add_ar_auth_bff

client_id = os.environ.get("AR_AUTH_CLIENT_ID")
if not client_id:
    raise RuntimeError(
        "Set AR_AUTH_CLIENT_ID — the public client registered on the auth "
        "server (PKCE, no secret)."
    )

secret = os.environ.get("AR_AUTH_BFF_SECRET")
if not secret:
    raise RuntimeError(
        "Set AR_AUTH_BFF_SECRET — 32+ random bytes (secrets.token_urlsafe(48)). "
        "Persist and share it across instances/restarts: there is no default "
        "key ring, so a changed secret logs everyone out."
    )

options = BffOptions(
    client_id=client_id,
    secret=secret,
    # authority="auth.adolfrey.com/api",           # the default
    # public_base_url only matters when the public URL differs from what the
    # app sees — e.g. behind a reverse proxy that strips a /application1/api
    # prefix. Cookies are then path-scoped to its path automatically.
    **({"public_base_url": os.environ["BFF_PUBLIC_BASE_URL"]}
       if os.environ.get("BFF_PUBLIC_BASE_URL") else {}),
)

app = FastAPI()
bff = add_ar_auth_bff(app, options)


# The SPA's boot probe.
@app.get("/me")
async def me(user: Dict[str, Any] = Depends(bff.auth)) -> Any:
    return {"sub": user.get("sub"), "claims": user}


# Unsafe-request demo: enforced signed double-submit XSRF header (X-CSRF-Token).
@app.post("/submit")
async def submit(user: Dict[str, Any] = Depends(bff.auth)) -> str:
    return "accepted"


# Static SPA last: no auth machinery on the wire for index.html itself.
app.mount(
    "/",
    StaticFiles(
        directory=os.path.join(os.path.dirname(__file__), "wwwroot"), html=True
    ),
    name="spa",
)
