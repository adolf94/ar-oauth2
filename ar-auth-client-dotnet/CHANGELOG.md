# Changelog

All notable changes to the Ar.Auth.OpenId packages are documented here.

## 1.3.0

### BFF integration for same-domain apps (`Ar.Auth.OpenId.AspNetCore`)

The headline feature: `AddArAuthBff` implements the Backend-for-Frontend pattern for SPAs
served from the same domain as their API. The API processes the OIDC login callback
(authorization-code flow + PKCE on a public client, no secret) and issues an app-local
**HttpOnly session cookie** — no access, refresh, or ID token ever reaches JavaScript.

- `AddArAuthBff(...)` / `app.UseArAuthBff()` — intercepts `/auth/login`, `/auth/callback`,
  `/auth/logout` (configurable paths), built on the framework's `AddOpenIdConnect`
  machinery (state, PKCE, correlation are framework-owned).
- App-scoped cookies: path + name prefix derived from the public base path, so multiple
  apps on one host never collide (`PublicBaseUrl` / `CookiePath` / `CookieNamePrefix`).
- **Silent renewal**: the refresh token is parked in its own DataProtection-encrypted
  cookie; expired sessions renew transparently, single-flight per token chain (the ar-auth
  server rotates refresh tokens on every use).
- **CSRF** (default on): `SameSite=Lax` + origin check + HMAC-signed double-submit
  `XSRF-TOKEN` cookie echoed via the `X-CSRF-Token` header (`X-XSRF-TOKEN` alias) —
  signed, so sibling-subdomain cookie-tossing fails. `BffCsrfMode.Off` disables.
- **Scheme composition**: with the BFF on, authentication picks Bearer header → app
  session cookie → (opt-in) auth-server session cookie; 401 challenges stay
  `WWW-Authenticate: Bearer`.
- **Extensibility**: `ArAuthHandler` subclass (`AddArAuthBff<THandler>()`, constructor
  injection) or `BffEvents` delegates — five hooks (`OnLoginRedirectingAsync`,
  `OnAuthenticatedAsync`, `OnRedirectingAsync`, `OnLogoutAsync`, `OnRenewedAsync`) that
  compose; security-critical work always runs and cannot be skipped by a hook.
- Runnable sample: `samples/BffSample` — the full SPA contract (links, `/me` boot probe,
  XSRF header wrapper) as living documentation.

> **Deployment note**: the session ticket and parked refresh token are encrypted with
> ASP.NET Core `DataProtection`. Multi-instance or restarting apps **must** share the
> key ring (Key Vault / blob / Redis). Renewal single-flight is per-process — scale-out
> requires sticky sessions or a single BFF instance.

### Session-cookie fallback (opt-in, all three packages)

The auth server's `ar_auth_session` cookie (shared-`Domain` variant) is now accepted as a
fallback credential when no Bearer header is present (`ArAuthOptions.AllowSessionCookie`).
Bearer always wins; a same-origin/allow-list CSRF guard applies; session JWTs carry
identity claims only (no roles/scopes — privilege enforcement keeps requiring Bearer).
Same-domain apps should prefer `AddArAuthBff`; this fallback serves the simpler
shared-cookie topology.

### Verification

76 integration/unit tests (in-proc stub OIDC provider + app-under-test), green on
net8.0 and net10.0 (net9.0 not exercised locally — runtime unavailable on the test
machine).

## 1.2.0

- Initial stable baseline: JWKS signature verification, token validation,
  authorization-code / refresh / client-credentials grants, ASP.NET Core JWT Bearer
  integration, Azure Functions Isolated Worker middleware.
