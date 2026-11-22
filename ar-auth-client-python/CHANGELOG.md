# Changelog

All notable changes to the `ar-auth-client` package are documented here.

## 1.3.1

### Added

- **Post-login landing control** (`BffOptions`): when the login link carries no
  `returnUrl`, the browser now lands at the captured same-origin `Referer`
  (`use_referrer_as_return_url=True`, cross-site referrers ignored) →
  `post_login_app_path` (explicit configured path) → the app's **public base
  path** — previously the bare site root "/", which sits outside the app's mount
  behind a prefix-stripping proxy (found in production: a prefixed deployment
  landed the user on the proxy's catch-all site after a successful login).
  An explicit `returnUrl` param keeps winning; all landing targets stay
  local-only validated (open-redirect guard).

### Fixed

- **BFF restart redirects now target the public login path.** Behind a
  prefix-stripping reverse proxy (e.g. Caddy `handle_path /gatekeeper/*`), the
  graceful-restart `Location: /auth/login` resolved outside the app's mount —
  the browser landed on the proxy's catch-all instead of the app's login page,
  masking the actual login failure. The restart redirects (callback failure,
  missing id_token claims, `on_authenticated` reject) now carry the
  browser-visible prefix, resolved by the same rule as `redirect_uri`:
  `public_base_url` path → `root_path` → `X-Forwarded-Prefix`.
- BFF callback failures are now logged (error description only — never codes
  or tokens); previously the graceful restart was silent and undebuggable
  server-side. Found in production on a prefix-stripped deployment
  (network-gatekeeper): a scope-gated login reject bounced the browser to the
  wrong path with no log trail.

## 1.3.0

> The release pipeline's version override published this build as 1.3.0;
> `pyproject.toml` (0.6.0 at the time) was realigned in 1.3.1.

### BFF integration for same-domain apps (FastAPI, `[fastapi]` extra)

The headline feature: `add_ar_auth_bff` implements the Backend-for-Frontend pattern for
SPAs served from the same domain as their API. The API processes the OIDC login callback
(authorization-code flow + PKCE on a public client, no secret) and issues an app-local
**HttpOnly session cookie** — no access, refresh, or ID token ever reaches JavaScript.

- `add_ar_auth_bff(app, BffOptions(...))` — serves `/auth/login`, `/auth/callback`,
  `/auth/logout` (configurable paths), built on AuthLib (state, PKCE, correlation are
  library-owned).
- App-scoped cookies: path + name prefix derived from the public base path, so multiple
  apps on one host never collide (`public_base_url` / `cookie_path` / `cookie_name_prefix`).
- **Silent renewal**: the refresh token is parked in its own Fernet-encrypted cookie;
  expired sessions renew transparently, single-flight per token chain (the ar-auth
  server rotates refresh tokens on every use), with a reuse window covering concurrent
  401 storms.
- **CSRF** (default on): `SameSite=Lax` + signed double-submit `XSRF-TOKEN` cookie echoed
  via the `X-CSRF-Token` header (`X-XSRF-TOKEN` alias) — signed, so sibling-subdomain
  cookie-tossing fails. `BffCsrfMode.OFF` disables.
- **Precedence**: `Depends(bff.auth)` resolves Bearer header → app session cookie →
  (opt-in) auth-server session cookie; 401 challenges stay `WWW-Authenticate: Bearer`.
- **Extensibility**: `ArAuthBff` subclass (`add_ar_auth_bff(..., bff=MyBff(options))`)
  or `BffEvents` delegates — five hooks (`on_login_redirecting`, `on_authenticated`,
  `on_redirecting`, `on_logout`, `on_renewed`) that compose; security-critical work
  always runs and cannot be skipped by a hook.
- Runnable sample: `samples/bff_sample` — the full SPA contract (links, `/me` boot probe,
  XSRF header wrapper) as living documentation; identical to the .NET `samples/BffSample`
  contract, so the same frontend works against either backend.

> **Deployment note**: the session ticket, parked refresh token, and CSRF tokens are all
> keyed to `BffOptions.secret` — there is **no default key ring**. Persist the secret and
> share it across instances/restarts (a changed secret logs everyone out). Renewal
> single-flight is per-process — scale-out requires sticky sessions or a single BFF
> instance.

### Session-cookie fallback (opt-in, all three integrations)

The auth server's `ar_auth_session` cookie (shared-`Domain` variant) is now accepted as a
fallback credential when no Bearer header is present
(`allow_session_cookie=True` on `ArAuthBearer`, `requires_auth`, `requires_auth_azure`,
and `BffOptions`). Bearer always wins; a same-origin/allow-list CSRF guard
(`SessionCookieGuard`) applies; session JWTs carry identity claims only (no
roles/scopes — privilege enforcement keeps requiring Bearer). Same-domain apps should
prefer `add_ar_auth_bff`; this fallback serves the simpler shared-cookie topology.

### Verification

124 integration/unit tests (real-socket stub OIDC provider + app-under-test on uvicorn —
the same harness design as the .NET SDK), green on Python 3.12
(`requires-python >= 3.9`).

## 0.5.0

- Initial stable baseline: JWKS signature verification, token validation,
  authorization-code / refresh / client-credentials / PAT grants, FastAPI, Flask, and
  Azure Functions integrations.
