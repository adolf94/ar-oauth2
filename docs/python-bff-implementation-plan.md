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

## Stage 1 — Core session-cookie validation, the fallback (S) — ✅ DONE

The shared-`Domain` variant (auth server's `ar_auth_session` cookie honored directly) —
the exact analog of the .NET resource-server work, all opt-in, default off.
(Landed after Stages 0–5: it was deferred by an explicit "continue stage 2", then built
as the prerequisite for Stage 6's third precedence leg — the .NET release order held:
fallback + BFF ship together.)

- [x] **T1.1 — `ArAuthClient.verify_session_token(token)`**: JWKS via the existing
      cache, `aud` = authority, claim `type == "session"`; returns identity claims only.
      Core, framework-agnostic.
- [x] **T1.2 — `SessionCookieGuard`** port: origin rules (same-origin or explicit
      allow-list, port-insensitive host compare) — port the .NET unit tests too.
      **Correction**: the .NET compares *full origins* case-insensitively with default
      ports trimmed (`Uri.GetLeftPart(Authority)` semantics), not hosts port-insensitively
      — the ported `extract_origin` follows the .NET, and the plan's "port-insensitive"
      wording was wrong. Port mismatch = rejection is covered by a test.
- [x] **T1.3 — Guard wiring**: `ArAuthBearer(allow_session_cookie=True,
      allowed_cookie_origins=[...])`, `requires_auth(allow_session_cookie=True, ...)`,
      `requires_auth_azure(...)` — precedence: Bearer header always wins; 401 challenge
      stays `WWW-Authenticate: Bearer`.
      Findings: Azure `func.HttpRequest` exposes no parsed cookie collection —
      `_get_request_cookie` parses the raw `Cookie` header via `http.cookies.SimpleCookie`;
      the `validate_request` programmatic helper stays Bearer-only (documented).
- [x] **T1.4 — Tests**: validation matrix (wrong `aud`/`type`, expired, bad signature),
      precedence, origin rejection, per-framework wiring.
      Suite: 34 new tests (`tests/test_stage1_session.py`) — guard matrix port,
      `verify_session_token` against the stub (valid / access-token rejected / garbage),
      FastAPI + Flask + Azure wirings incl. Bearer-wins and off-by-default; **113/113 green**.

## Stage 2 — BFF routes: login / callback / logout (L) — ✅ DONE

The OIDC core. Built on AuthLib machinery — correlation logic is not hand-rolled.

- [x] **T2.1 — `BffOptions` + path resolution** (`src/ar_auth/bff.py`): all §3.8 values
      — `login_path`/`callback_path`/`logout_path` (defaults `/auth/login`, `/auth/callback`,
      `/auth/logout`), `public_base_url`, `cookie_path`, `cookie_name_prefix`,
      `session_expiry` (8h), `correlation_ttl` (10 min), `csrf` mode, `secret`,
      `secure_cookies`. Cookie scoping is options-static (explicit → public path → "/"),
      mirroring the .NET rule; `redirect_uri` is per-request
      (public_base_url → `root_path` → `X-Forwarded-Prefix` → bare host). Fail-fast
      validation in `__post_init__` via `ConfigurationError`.
- [x] **T2.2 — `ArAuthBff` + `add_ar_auth_bff(app, options)`**: login validates the
      local-only `returnUrl`, stores it in the correlation session, and delegates to
      AuthLib's `authorize_redirect` (state + nonce + PKCE S256 are library-owned).
      The correlation cookie is a **scoped `SessionMiddleware` instance** —
      itsdangerous-signed with the derived "state" key, prefixed name, path-scoped,
      `Max-Age=600`, HttpOnly + Lax; Starlette deletes it automatically once the
      callback clears the state (empty modified session).
- [x] **T2.3 — Callback**: AuthLib's `authorize_access_token` validates state, exchanges
      code+PKCE, and fully validates the `id_token` (signature via JWKS with kid-refetch,
      `iss` from discovery, `aud` = client_id, `exp`, `nonce`; `at_hash` only when
      present). A claims-only session ticket is issued (HttpOnly, Lax, path-scoped,
      `Secure` from the configured scheme). Consumed code / state mismatch /
      provider error → graceful redirect to login — never a 500 (verified by test).
- [x] **T2.4 — Logout**: clears the session cookie (path-scoped), validates `returnUrl`.
- [x] **T2.5 — Warmup**: discovery + JWKS prefetched at startup. This Starlette (1.9)
      dropped `add_event_handler`, so warmup chains onto the app's lifespan via
      `router.lifespan_context` composition — the app's own lifespan is preserved and
      an unreachable authority fails startup (fail-fast, mirroring `BffOidcWarmup`).
- [x] **T2.6 — Tests** (`tests/test_stage2_bff.py`, 17 tests; app-under-test
      `tests/bff_app.py` runs on a real uvicorn loopback port like the .NET
      `BffTestApp` on Kestrel): full round-trip, PKCE/state/redirect_uri authorize
      shape, cookie attributes, open-redirect matrix, consumed-code replay,
      forged-state callback, logout, `public_base_url` scoping/prefix, warmup.
      Suite: 47/47 green.

**Findings:** (1) `MismatchingStateError` (replayed callback) is an `OAuthError`
subclass; the invalid_grant token response surfaces as authlib `OAuth2Error` — the
callback catches both. (2) A replayed callback never re-issues a session but the
user's existing one persists — expected. (3) `Secure` is config-derived
(scheme of `public_base_url`/authority), not per-request `SameAsRequest` like .NET —
documented tradeoff (TLS-terminating proxies should set `secure_cookies=True`).
(4) API sharp edge: options validate in `__post_init__`; post-construction mutation
does not revalidate — construct with final values.

## Stage 3 — Parked refresh + single-flight renewal (M) — ✅ DONE

- [x] **T3.1 — `_RefreshStore`**: Fernet-encrypted parked cookie (`{prefix}ar_bff_refresh`,
      HttpOnly, Lax, path-scoped, 30-day TTL via `refresh_cookie_ttl` — not
      session-aligned), key derived from the secret (`|ar-bff|refresh` label). Garbage
      values read as absent.
- [x] **T3.2 — Token stripping**: the session ticket is claims-only (verified by test —
      the ticket payload is decoded and asserted free of access/refresh/ID tokens); the
      callback parks the refresh token and drops access/ID tokens outright; logout clears
      both cookies.
- [x] **T3.3 — `SessionRenewer`** (methods on `ArAuthBff`): single-flight per-chain
      `asyncio.Lock` keyed by SHA-256(refresh token) + a 2-minute `renewal_reuse_window`
      (now a `BffOptions` field — see findings). Own `/token` call via warm discovery
      (`httpx`): 400/401 → `REJECTED` (burn the parked cookie), other failures/parse →
      `UNAVAILABLE` (keep it). Claims rebuilt from the refreshed id_token via AuthLib
      `parse_id_token(nonce=None)` — nonce skipped on renewal by design; signature, iss,
      aud, exp still enforced.
- [x] **T3.4 — Renewal trigger**: pure-ASGI `_BffRenewalMiddleware` (outermost) —
      anonymous request + parked cookie + no `Authorization` header, BFF routes exempt,
      valid sessions skip. RENEWED claims ride the request scope (authenticated in
      place); its Set-Cookie headers are appended to ANY response kind, not just
      redirects (mirrors the .NET middleware).
- [x] **T3.5 — Tests** (`tests/test_stage3_bff.py`, 10 tests): parking attributes +
      opaque value, claims-only ticket, logout clears both, expiry → silent renewal
      (count == 1, both cookies re-issued, rotated), concurrent single-flight (5 parallel
      tabs → exactly one `/token` call), Bearer exemption, revoked → burn, replayed
      consumed token (both window semantics), transient (stopped stub) → cookie kept.
      Suite: 57/57 green.

**Findings:** (1) **Reuse-window semantics**: a stale tab replaying the *consumed*
predecessor token inside the window is answered by the chain's cached renewal (the
parallel-401 storm cover) — only outside the window does the real `/token` attempt burn.
The test asserts both; this forced `renewal_reuse_window` to become an option (default
2 min, .NET hard-coded). (2) **h11 trap**: the cookie-scratch `Response()` carries a
default `content-length` header — appending its raw headers to a real response yields
"conflicting Content-Length" and a dropped connection; only `set-cookie` headers are
copied now. (3) itsdangerous timestamps have second granularity — renewal tests sleep
2.2 s for 1 s sessions. (4) The renewal uses a per-call `httpx.AsyncClient` (renewals
are rare) vs .NET's pooled client — noted, not optimized.

## Stage 4 — CSRF signed double-submit layer (S) — ✅ DONE

Parallel with Stage 3 (independent files, both depend on 2) — landed after it.

- [x] **T4.1 — Issuance** (`_CsrfTokenService`): HMAC-SHA256-signed random 32-byte blob
      (`b64(raw).b64(sig)`, csrf-purpose subkey, `hmac.compare_digest` on check), issued
      as a **JS-readable** `{prefix}XSRF-TOKEN` cookie (HttpOnly off by design, Lax,
      path-scoped, session-lifetime-aligned) at the callback and at silent renewal.
- [x] **T4.2 — Enforcement**: lives in the renewal middleware — **after** renewal (a
      POST that renewed is authenticated and passes on its OLD still-signed token),
      before the app. Unsafe methods only; Bearer requests exempt (attacker JS cannot
      forge an Authorization header); anonymous requests exempt (the app answers 401 —
      403 would mislead the SPA); BFF routes exempt; safe = GET/HEAD/OPTIONS/TRACE.
      Header `X-CSRF-Token` with `X-XSRF-TOKEN` accepted as the Angular-style alias;
      the header must echo the cookie exactly AND carry a valid signature — a tossed
      sibling-subdomain cookie fails the HMAC. Mismatch → 403 short-circuit, and
      renewal cookies still ride the 403 response. `csrf=BffCsrfMode.OFF` opts out
      (no issuance, no check).
- [x] **T4.3 — Tests** (`tests/test_stage4_bff.py`, 12 tests): issuance attributes +
      readable + signed shape, valid/wrong/missing header, alias, **tossed-cookie
      rejection** (double-submit matches, signature fails), anonymous stays 401,
      GET exempt, Bearer exempt, logout clears XSRF, off mode (no cookie, no check),
      renewal interplay. Suite: 69/69 green.

**Findings:** (1) **Naming deviation**: enum members are Python-idiomatic
(`BffCsrfMode.OFF` / `SIGNED_DOUBLE_SUBMIT`) where the plan text said `.Off`. (2)
**Post-idle stale-POST semantics** (surfaced by the renewal-interplay test): the XSRF
cookie is session-lifetime-aligned, so after full expiry the browser has dropped the
pair — a stale SPA POST still triggers renewal (authenticated in place) but fails the
double-submit check → 403; the SPA re-probes with a GET, picks up the fresh pair issued
alongside the renewed session, and retries. Same story as .NET; the test documents it.

## Stage 5 — Extensibility surface (M) — ✅ DONE

- [x] **T5.1 — Hooks** mirroring the five .NET virtuals as overridable ``async``
      methods on `ArAuthBff` (each base implementation fires the matching
      `BffEvents` delegate; sync **and** async delegates both work via
      `inspect.isawaitable`):
      `on_login_redirecting` (extra authorize params via `context.extra_params`;
      return-URL adjustment — **re-sanitized** by base),
      `on_authenticated` (enrich/replace `claims` — what gets signed into the
      session cookie; return-URL adjustment — re-sanitized; `reject()` aborts with
      a graceful login-path redirect, **no session/parked/XSRF cookies written**),
      `on_redirecting` (the .NET `ReturnUri` trap ported: the hook owns the landing
      URL end-to-end, its result used **verbatim**),
      `on_logout` (observes the valid-session claims + return URL; base clears
      cookies and redirects regardless),
      `on_renewed` (fired on **both** the leader and reuse paths, mirroring the
      .NET `IssueAsync`; claim enrichment propagates into the fresh cookie).
      Contexts `BffRedirectContext` / `BffAuthenticatedContext` / `BffLogoutContext`
      / `BffRenewalContext`; delegates on `BffEvents` (set via `BffOptions.events`).
      Subclass registration: `add_ar_auth_bff(app, options, bff=MyBff(options))` —
      plain constructor injection, no DI container needed. Same Stage-5
      interpretation as .NET, stated on the class: security-critical work lives in
      the pipeline components and ALWAYS runs; overriding a hook cannot skip it —
      not calling `super()` only opts out of the delegate of the same name.
- [x] **T5.2 — Tests** (`tests/test_stage5_bff.py`, 10 tests): extra authorize
      params, login-hook URL re-sanitization, claims enrichment, reject-aborts
      (no cookies issued), authenticated-hook URL re-sanitization, verbatim landing
      rewrite, logout audit, renewal hook fires + enrichment propagates,
      subclass-with-super composition, subclass-without-super opts out.
      Suite: 79/79 green.

## Stage 6 — Precedence composition (S) — ✅ DONE

- [x] **T6.1 — Auth dependency**: Bearer header → app session cookie (renewal trigger
      included) → opt-in auth-server session-cookie fallback. Challenges stay
      `WWW-Authenticate: Bearer`. Expired app cookie routes to renewal, never falls
      through to the shared cookie while a parked refresh exists (renewal is strictly
      better — mirrors the .NET Stage 6 finding).
      Built as ``ArAuthBff.auth`` — an async method usable directly as
      ``Depends(bff.auth)`` (the .NET policy scheme's analog). Fallback options live on
      ``BffOptions`` (``allow_session_cookie``/``session_cookie_name``/
      ``allowed_cookie_origins``). The Bearer leg validates via joserfc against
      AuthLib's warm JWKS + manual iss/exp (60s leeway) — no audience enforcement by
      default (mirrors ``ArAuthClient.verify_token``); the shared-session leg lazily
      constructs a sync ``ArAuthClient`` (discovery + JWKS cached after first hit).
      Presence chain preserved: a garbage/expired app cookie blocks the shared-cookie
      fallthrough even when that cookie is valid.
- [x] **T6.2 — Tests**: precedence order, renewal-over-fallback preference, `/claims`
      shape (raw `sub` — no remapping caveat).
      11 tests in `tests/test_stage6_bff.py` (`/claims` endpoint added to the test
      app): Bearer-wins, invalid-Bearer-401-with-valid-session, wrong-issuer forged
      token, app-session identity parity with `/me`, anonymous 401 +
      `WWW-Authenticate: Bearer`, fallback on/off, non-session-token rejection, evil
      origin, renewal-over-fallback (1s session + parked refresh: renewed sub wins,
      one grant), presence-chain (garbage app cookie + valid shared cookie → 401).
      Suite: **124/124 green**.

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
