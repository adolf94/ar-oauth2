# Implementation Plan: Python BFF & Cookie Auth — `ar-auth-client-python`

Port of the .NET 1.3.0 same-domain story (`docs/cookie-auth-plan.md` §3–§5, built per
`docs/bff-implementation-plan.md`) to the Python SDK, so a Python API hosted on the same
domain as its SPA gets the **identical** integration: backend-processed OIDC callback,
app-local HttpOnly session cookie, silent renewal, signed double-submit CSRF — same
routes, same cookie names, same SPA contract. A same-domain SPA cannot tell which stack
its API is.

**Target package:** `ar-auth-client-python` (stays one package; BFF under the `[fastapi]`
extra) · **Release version:** 0.6.0

---

## What carries over unchanged (verified facts — no backend work needed)

| Fact | Source |
|---|---|
| Backend stays a stateless Bearer-only issuer | design §2 |
| Session JWT: `aud` = authority, claim `type == "session"`, identity claims only (no roles/scopes) | .NET `ValidateSessionTokenAsync` + tests |
| Public client + PKCE S256, no secret | design §3.4 |
| Refresh rotation is one-time-use; refresh grant returns `id_token` when `openid` granted (nonce empty — renewal must NOT validate nonce) | backend `TokenFunction`, .NET Stage 3 finding |
| Cookie scoping: `Path` + name prefix derived from the public path (`/application1/` → prefix `application1.`, root → none), applied to ALL BFF cookies | .NET T0.2 |
| CSRF = Lax + origin check + signed double-submit, default-on | design §4, .NET Stage 4 |
| SPA contract: links + `/me` boot probe + XSRF header — no JS library, no tokens in JS | design §5 |
| Callback idempotency: consumed code → graceful redirect to login, never a 500 | .NET §10.B finding |

## .NET → Python deltas (read before Stages 2–4)

1. **No DataProtection.** .NET self-provisions a key ring; Python must demand an explicit
   secret. One configured secret (T0.3); per-purpose keys derived by SHA-256/HKDF
   labeling (state, csrf, session ticket) for HMAC signing; the parked refresh cookie is
   **encrypted** (`cryptography.Fernet`). Startup fails fast when the secret is missing —
   no insecure default. Deployment box becomes *more* important than in .NET: persist and
   share the secret across instances/restarts or every deploy logs everyone out.
2. **No `AddOpenIdConnect`.** The "build on framework machinery, don't hand-roll
   correlation" role is played by **AuthLib** (T0.2) — state, PKCE, and correlation are
   library-owned. `id_token` validation reuses the existing PyJWT path
   (`verify_token`, `aud` = client_id) rather than AuthLib's.
3. **Sync client stays sync.** Existing `ArAuthClient` is `requests`-based and frozen for
   compatibility; the BFF talks to the authority via `httpx.AsyncClient` with cached
   discovery, warmed at startup (mirror of `BffOidcWarmup`).
4. **No claim remapping.** PyJWT keeps raw claim names (`sub` stays `sub`) — the .NET
   claim-shape caveat (JwtBearer/legacy handler renames) does not exist here; tests
   assert `sub` directly everywhere.
5. **Single-flight** = `asyncio` lock dict keyed by SHA-256 of the refresh token, 2-min
   waiter window — same semantics as `BffSessionRenewer`: definitive 400/401 burns the
   parked cookie; transient transport/parse failures keep it.

---

## Stage overview

| Stage | Theme | Depends on | Rough size |
|---|---|---|---|
| 0 | Groundwork decisions + test harness | — | XS |
| 1 | Core session-cookie validation (fallback) | 0 | S |
| 2 | BFF routes: login/callback/logout (OIDC core) | 0, 1 | L |
| 3 | Parked refresh + single-flight renewal | 2 | M |
| 4 | CSRF signed double-submit layer | 2 (parallel with 3) | S |
| 5 | Extensibility surface (hooks) | 2–4 | M |
| 6 | Precedence composition (Bearer > app cookie > session cookie) | 3, 4 | S |
| 7 | Docs, sample, release (0.6.0) | 1–6 | M |

Definition of done: all stages checked with findings recorded (same convention as the
.NET plan), `pytest` green, README mirroring the .NET 1.3.0 structure, version 0.6.0 +
CHANGELOG.

---

## Stage 0 — Groundwork decisions + harness (XS) — ✅ DONE

- [x] **T0.1 — Framework scope: MADE.** The BFF ships **FastAPI/Starlette-only**
      (mounted as routes on the FastAPI app). The *session-cookie fallback* is cheap and
      framework-agnostic, so it wires into all three existing guards: FastAPI
      `ArAuthBearer`, Flask `requires_auth`, Azure `requires_auth_azure`. Flask BFF and
      Django are out.
- [x] **T0.2 — OIDC machinery: MADE.** `authlib.integrations.starlette_client.OAuth`
      owns state/PKCE/correlation (async, PKCE S256). New deps under the `[fastapi]`
      extra: `authlib`, `httpx`, `itsdangerous`, `cryptography` (added to pyproject;
      `authlib` 1.9.10 installed; httpx/itsdangerous/cryptography were already in the
      dev venv).
- [x] **T0.3 — Secret management: MADE.** Explicit required `secret`; per-purpose
      subkeys via labeled SHA-256 derivation; Fernet for the parked refresh cookie. No
      default, fail fast at app construction.
- [x] **T0.4 — Test harness: MADE, with a deviation.** `tests/stub_oidc.py` is a direct
      port of the .NET `StubOidcServer` (discovery, RSA JWKS, /authorize with PKCE
      mandatory, /token with S256 verification, one-time-use rotating refresh with
      burn-on-read, `create_access_token(sub)` / `create_session_token(sub)` /
      `refresh_grant_count` / `revoke_all_refresh_tokens`). It runs on a **random
      loopback port via uvicorn** (dev-only dep) instead of ASGI-in-memory transport —
      the SDK's `PyJWKClient` uses urllib and `ArAuthClient` uses `requests`, which mock
      transports cannot serve; real sockets keep every client library honest (same
      approach as the .NET Kestrel stub). **Deviation: `pytest-asyncio` dropped** — sync
      tests suffice, so the dep was never added. Findings recorded: Starlette now
      requires `python-multipart` even for urlencoded `request.form()`, so the stub
      parses token-request bodies directly. 10 smoke tests
      (`tests/test_stage0_harness.py`) prove the stub before any BFF code exists.
- [x] **T0.5 — Python floor: MADE.** `requires-python` bumped to `>=3.9` in pyproject.
- [x] **T0.6 — Version & packaging: MADE.** 0.6.0 at release (T7.4), single package,
      BFF behind the `[fastapi]` extra.

## Stage 1 — Core session-cookie validation, the fallback (S)

The shared-`Domain` variant (auth server's `ar_auth_session` cookie honored directly) —
the exact analog of the .NET resource-server work, all opt-in, default off.

- [ ] **T1.1 — `ArAuthClient.verify_session_token(token)`**: JWKS via the existing
      cache, `aud` = authority, claim `type == "session"`; returns identity claims only.
      Core, framework-agnostic.
- [ ] **T1.2 — `SessionCookieGuard`** port: origin rules (same-origin or explicit
      allow-list, port-insensitive host compare) — port the .NET unit tests too.
- [ ] **T1.3 — Guard wiring**: `ArAuthBearer(allow_session_cookie=True,
      allowed_cookie_origins=[...])`, `requires_auth(allow_session_cookie=True, ...)`,
      `requires_auth_azure(...)` — precedence: Bearer header always wins; 401 challenge
      stays `WWW-Authenticate: Bearer`.
- [ ] **T1.4 — Tests**: validation matrix (wrong `aud`/`type`, expired, bad signature),
      precedence, origin rejection, per-framework wiring.

## Stage 2 — BFF routes: login / callback / logout (L)

The OIDC core. Build on AuthLib machinery — do not hand-roll correlation logic.

- [ ] **T2.1 — `BffOptions` + `BffPathResolver` port**: `login_path`/`callback_path`/
      `logout_path` (defaults `/auth/login`, `/auth/callback`, `/auth/logout`),
      `public_base_url`, `cookie_path`, `cookie_name_prefix`, `session_expiry` (8h),
      `csrf` mode, `secret`. Resolver precedence: `public_base_url` → Starlette
      `root_path` (the `UsePathBase` analog) → `X-Forwarded-Prefix` → bare host; produces
      the `redirect_uri` (must match client registration exactly), browser cookie path,
      and cookie-name prefix. Fail-fast validation (bad paths, non-positive expiry,
      malformed `public_base_url`).
- [ ] **T2.2 — `ArAuthBff` class + `add_ar_auth_bff(app, ...)`**: intercepts login →
      validated local `return_url` + state/PKCE via AuthLib + short-TTL single-use
      correlation cookie (prefix + path per T0.2 rule) → 302 to `/authorize`.
- [ ] **T2.3 — Callback**: state validation, code+PKCE exchange, `id_token` validated
      via the existing PyJWT path, **claims-only session ticket** issued (HttpOnly,
      SameSite=Lax, path-scoped, Secure-on-https), 302 to the return URL. Consumed code
      / `invalid_grant` → graceful redirect to login, never a 500.
- [ ] **T2.4 — Logout**: clears all app-local cookies (session, parked refresh, XSRF),
      302 to return URL.
- [ ] **T2.5 — Warmup**: FastAPI startup event fetches discovery + JWKS via a
      per-app-lifetime `httpx.AsyncClient` (mirror of `BffOidcWarmup`).
- [ ] **T2.6 — Tests**: full round-trip against the stub, `return_url` validation
      matrix, consumed-code idempotency, path/prefix matrix, cookie attributes.

## Stage 3 — Parked refresh + single-flight renewal (M)

- [ ] **T3.1 — `RefreshStore`**: Fernet-encrypted parked-refresh cookie (HttpOnly, Lax,
      path-scoped, prefixed name); key from the configured secret.
- [ ] **T3.2 — Token stripping**: the session ticket carries validated claims only —
      access/refresh/ID tokens never enter any readable or session cookie.
- [ ] **T3.3 — `SessionRenewer`**: single-flight `asyncio` locks keyed by
      SHA-256(refresh token), 2-min waiter window; makes its own `/token` call via warm
      discovery to distinguish definitive 400/401 (burn the parked cookie) from transient
      failure (keep it); rebuilds claims from the fully validated refreshed `id_token`
      (nonce deliberately skipped on renewal); reissues both cookies.
- [ ] **T3.4 — Renewal trigger**: any anonymous request with a parked cookie present and
      no Bearer header (mirrors the .NET middleware placement).
- [ ] **T3.5 — Tests**: expiry → silent renewal round-trip; concurrent single-flight
      (exactly one stub `/token` call); rotation burn-on-reuse; definitive vs transient;
      claims rebuild.

## Stage 4 — CSRF signed double-submit layer (S)

Parallel with Stage 3 (independent files, both depend on 2).

- [ ] **T4.1 — Issuance**: HMAC-signed `XSRF-TOKEN` cookie (deliberately JS-readable,
      csrf-purpose subkey), issued at callback and renewal.
- [ ] **T4.2 — Enforcement** (after renewal, before authorization) on unsafe methods:
      request cookie vs `X-CSRF-Token` header (`X-XSRF-TOKEN` accepted as an alias) with
      signature check — sibling-subdomain cookie-tossing fails the HMAC. 403 on
      authenticated-mismatch, 401 for anonymous; `csrf=off` mode for opt-out.
- [ ] **T4.3 — Tests**: round-trip, tossed/unsigned cookie rejected, alias header,
      off mode, 401/403 semantics.

## Stage 5 — Extensibility surface (M)

- [ ] **T5.1 — Hooks** mirroring the five .NET virtuals as overridable methods on
      `ArAuthBff`: `on_login_redirecting` (extra authorize parameters),
      `on_authenticated` (enrich claims or `reject()`), `on_redirecting` (final
      post-login landing rewrite — port the .NET `ReturnUri` trap: the hook owns the
      redirect target end-to-end), `on_logout`, `on_renewed`. Callback-style wiring
      (kwargs) for non-subclass users. Same Stage-5 interpretation as .NET: base
      implementations own every security-critical step; overriding cannot skip them —
      not calling `super()` only opts out of the callback of the same name.
- [ ] **T5.2 — Tests**: subclass + callback variants, `reject()` path, landing rewrite.

## Stage 6 — Precedence composition (S)

- [ ] **T6.1 — Auth dependency**: Bearer header → app session cookie (renewal trigger
      included) → opt-in auth-server session-cookie fallback. Challenges stay
      `WWW-Authenticate: Bearer`. Expired app cookie routes to renewal, never falls
      through to the shared cookie while a parked refresh exists (renewal is strictly
      better — mirrors the .NET Stage 6 finding).
- [ ] **T6.2 — Tests**: precedence order, renewal-over-fallback preference, `/claims`
      shape (raw `sub` — no remapping caveat here).

## Stage 7 — Docs, sample, release (M)

- [ ] **T7.1 — README rewrite** mirroring the .NET 1.3.0 structure: BFF headline
      (setup, flow, options, SPA contract, extensibility), **secret-provisioning
      deployment box** (persist + share the secret — no default key ring exists),
      local-dev https/proxy box (mkcert, `X-Forwarded-Proto`/`-Prefix`), session-cookie
      section demoted to the legacy shared-`Domain` fallback.
- [ ] **T7.2 — Sample app**: FastAPI + static `index.html` implementing the exact SPA
      contract (port of `ar-auth-client-dotnet/samples/BffSample`) — living
      documentation and manual regression harness.
- [ ] **T7.3 — Doc sync**: `docs/cookie-auth-plan.md` §6/§7 — Python port built;
      this plan checked off with findings.
- [ ] **T7.4 — Release**: version 0.6.0 in `pyproject.toml`, `CHANGELOG.md` created,
      full `pytest` run on supported interpreters.

---

## Explicitly out of scope (tracked elsewhere)

| Item | Where |
|---|---|
| Backend changes of any kind | None needed — verified in the .NET effort |
| JS client (`ar-auth-client`) | Frozen Bearer-only (cross-domain role) |
| Flask BFF / Django | Validation fallback only for Flask; no Django support |
| Multi-instance distributed renewal lock | Single-instance topology; document sticky-sessions caveat in README |
| Cross-site cookies (`SameSite=None` Phase 2) | Rejected unless a real Safari-proof case appears |
| Management carve-out | `docs/cookie-auth-plan.md` §7 |

## Sequencing notes

- Stage 4 can proceed **in parallel** with Stage 3 (different files, both depend on 2).
- Stage 1 is independent of the BFF stages and can land/ship first (mirrors the .NET
  release order: fallback shipped with 1.3.0 alongside the BFF).
- Each stage lands with its tests green and gets checked off here with findings, as
  work completes.
