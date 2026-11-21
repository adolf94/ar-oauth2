# ArAuth BFF sample

The same-domain topology from `docs/cookie-auth-plan.md` §5: the API processes the
OIDC login callback and issues an app-local **HttpOnly session cookie**. No
access, refresh, or ID token ever reaches JavaScript — the SPA
(`wwwroot/index.html`) is two links, a boot probe, and an XSRF header wrapper.
No frontend auth library.

## Run

1. Register a **public client** on the auth server (PKCE, no secret) whose
   redirect URI is `<public URL>/auth/callback`.

2. From the repo root (`ar-auth-client-python/`):

   ```bash
   AR_AUTH_CLIENT_ID=my-app \
   AR_AUTH_BFF_SECRET="$(uv run python -c 'import secrets; print(secrets.token_urlsafe(48))')" \
     uv run --extra fastapi uvicorn samples.bff_sample.main:app --port 8443
   ```

   Optional, **only** behind a prefix-stripping reverse proxy where the public
   URL differs from what the app sees: add
   `BFF_PUBLIC_BASE_URL=https://host/application1/api`. Cookies are then
   path-scoped (and prefixed) to that path automatically.

3. Open `http://127.0.0.1:8443/` → **Sign in** → the boot probe shows your `sub`.
   **POST with XSRF header** exercises the signed double-submit CSRF check.

## Production notes

- `AR_AUTH_BFF_SECRET` is load-bearing: the session ticket, the parked refresh
  token, and the CSRF tokens are all keyed to it. There is **no default key
  ring** — persist it and share it across instances/restarts, or every deploy
  logs everyone out.
- Renewal single-flight is per-process: horizontally scaled deployments need
  sticky sessions or a single BFF instance.
- The SPA contract is identical to the .NET `samples/BffSample` — same links,
  same `/me` boot probe, same `X-CSRF-Token` wrapper — so the same frontend
  works against either backend.
