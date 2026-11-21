# Implementation Plan: `AddArAuthBff` — Same-Domain BFF Authentication

Build plan for the one remaining piece of the same-domain authentication story
(`docs/cookie-auth-plan.md`, §3–§5). Everything else in that design doc is either
shipped or deliberately deferred.

**Target package:** `ar-auth-client-dotnet/src/Ar.Auth.OpenId.AspNetCore` (+ core types in
`Ar.Auth.OpenId`) · **Target frameworks:** net8.0 / net9.0 / net10.0

---

## Stage overview

| Stage | Theme | Depends on | Rough size |
|---|---|---|---|
| 0 | Groundwork decisions | — | XS |
| 1 | Options & contracts (core types) | 0 | S |
| 2 | Login/callback/logout interception (OIDC core) | 1 | L |
| 3 | Session issuance + parked refresh + single-flight renewal | 2 | M |
| 4 | CSRF signed double-submit layer | 2 (parallel with 3) | S |
| 5 | Extensibility surface (hooks + events) | 2–4 | M |
| 6 | Policy-scheme integration + precedence | 3, 4 | S |
| 7 | Docs, sample, release | 1–6 | M |

Definition of done (whole plan): all stages checked, full test suite green on net8/net10
(net9 environment permitting), `docs/cookie-auth-plan.md` §6 updated to "built", packages
version-bumped and building.

---

## Stage 0 — Groundwork decisions (XS) — ✅ DONE

- [x] **T0.1 — Test harness decision: MADE.** Integration tests with
      `WebApplicationFactory`/`TestServer` + an in-proc stub OIDC provider (CI-repeatable);
      a minimal same-domain sample app lands as the Stage 7 living documentation.
- [x] **T0.2 — Cookie naming rule: MADE.** Cookie-name prefix derives from the effective
      cookie path ("/application1/" → "application1.", "/app/api/" → "app-api.", root "/"
      → none), applied to session/refresh/correlation/XSRF cookies; explicit
      `CookieNamePrefix` overrides.
- [x] **T0.3 — Version & packaging: MADE.** Ship inside existing
      `Ar.Auth.OpenId.AspNetCore`, version 1.3.0 at release (T7.4); no new package.

## Stage 1 — Options & contracts (S) — ✅ DONE

- [x] **T1.1 — `BffOptions`** (`src/Ar.Auth.OpenId.AspNetCore/BffOptions.cs`): all §3.8
      values — `LoginPath` / `CallbackPath` / `LogoutPath` (defaults `/auth/login`,
      `/auth/callback`, `/auth/logout`), `PublicBaseUrl`, `CookiePath`, `SessionExpiry`
      (8h), `Csrf` (`BffCsrfMode.SignedDoubleSubmit` default-on), `CookieNamePrefix`,
      `Events`.
- [x] **T1.2 — Path duality helper** (`BffPathResolver.cs`): precedence
      PublicBaseUrl → **PathBase (UsePathBase — authoritative, request path already
      includes the prefix)** → X-Forwarded-Prefix → bare host. Produces `redirect_uri`
      (must match client registration exactly), browser-visible cookie path, cookie-name
      prefix. Config validation fails fast (bad paths, non-positive expiry, malformed
      PublicBaseUrl).
- [x] **T1.3 — Context types** (`BffContexts.cs`, `BffEvents.cs`): `BffRedirectContext`
      (ReturnUrl + ExtraParameters), `BffAuthenticatedContext` (Principal, Reject()),
      `BffLogoutContext`, `BffRenewalContext`; five delegate hooks on `BffEvents`.
- [x] **T1.4 — Unit tests** (`tests/…/BffStage1Tests.cs`, 18 tests): options defaults,
      resolver matrix (bare host / UsePathBase / forwarded prefix / explicit PublicBaseUrl /
      overrides), validation rejections, context contracts. 44/44 green on net8/net10.

## Stage 2 — Login / callback / logout interception (L)

The OIDC core. Build on `AddOpenIdConnect` machinery (correlation, state, PKCE) —
do not hand-roll correlation logic. *(Design doc §3.3, §3.6.)*

- [x] **T2.1 — OIDC handler wiring**: configure `AddOpenIdConnect` from `AddArAuth`'s
      authority: PKCE forced, public-client mode (no secret), scope handling, correlation
      cookie options (name prefix per T0.2, `Path` = public app path, short TTL,
      single-use), `CallbackPath` binding.
- [x] **T2.2 — `auth_login` interception**: generate state + PKCE + validated local
      `returnUrl` → correlation cookie → 302 to `/authorize` with
      `redirect_uri = PublicBaseUrl + CallbackPath`.
- [x] **T2.3 — `auth_callback` interception**: state validation via correlation cookie,
      cookie deleted on read, code exchange, principal build; **idempotent failure path** —
      Back-button/refresh with a consumed code (`invalid_grant`) redirects gracefully to
      `LoginPath`, never 500 (design doc §10.B).
- [x] **T2.4 — `auth_logout` interception**: local cookie cleanup (session, refresh, XSRF)
      → redirect to `returnUrl`. No auth-server end-session (verified absent & unneeded,
      design doc §10.A).
- [x] **T2.5 — Interception bypass**: login/callback/logout paths bypass `[Authorize]`
      by construction (middleware order), verified with a test that they respond 302 while
      protected endpoints 401.
- [x] **T2.6 — Integration test (harness from T0.1)**: full redirect round-trip against
      stub OIDC — login → authorize → callback → session cookie set → `me` returns identity;
      plus state-mismatch rejection (login CSRF), tampered `returnUrl` rejection
      (open-redirect guard), consumed-code graceful retry.

**Stage 2 findings (recorded):**
- **Options validation ordering trap (cost ~1h)**: on .NET 8+ `OptionsFactory` runs
  scheme validation (`OpenIdConnectOptions.Validate()` — demands Authority/MetadataAddress)
  **after `Configure` but before `PostConfigure`**. Wiring Authority/ClientId/CallbackPath
  in a `PostConfigure` throws on first options resolution. All scheme options that
  validation depends on must be written in the `Configure` phase
  (`OptionsBuilder.Configure<TDep...>` — DI deps work there too). `PostConfigure` remains
  correct only for `AuthenticationOptions` default-scheme overrides (not validated).
- `CookieBuilder` has `SecurePolicy` (nullable enum), not `Secure`; per-response
  `CookieOptions` has `Secure` (bool), not `SecurePolicy`.
- `AuthenticationBuilder.AddOpenIdConnect` has no single-string overload — use
  `(scheme, _ => { })`.
- Namespace collision in tests: `Ar.Auth.OpenId.Tests` walks up to `Ar.Auth.OpenId`, whose
  core-package `AddArAuth(IServiceCollection)` overload silently wins over the AspNetCore
  one — call `ArAuthAspNetCoreExtensions.AddArAuth(...)` explicitly in test harnesses.
- `WebApplication.CreateSlimBuilder()` does not register authorization services — test
  harness must call `AddAuthorization()` itself.
- Correlation/nonce cookies: `SecurePolicy = SameAsRequest` for http local-mock authorities,
  `Always` otherwise; session cookie `SameAsRequest` always (proxy must send
  X-Forwarded-Proto).
- The metadata warm-up hosted service (`BffOidcWarmup`) is in: it sidesteps the
  no-blocking-metadata-fetch behavior of modern OIDC handlers on the first redirect.
- 10 integration tests (`BffStage2Tests`): login redirect (PKCE S256/state/nonce/
  correlation/redirect_uri), full round trip (`/me` → `user-42`, correlation consumed,
  session issued), tampered state → 302 login, burned code → 302 login, foreign +
  protocol-relative returnUrl → sanitized, protected `/me` → 401 Bearer while `/public` →
  200, logout clears session, OnAuthenticated enrich + reject hooks. Green on net8/net10.

## Stage 3 — Session issuance + parked refresh + renewal (M)

- [x] **T3.1 — Session issuance** at callback: `SignInAsync` with app-local cookie
      (encrypted ticket, `Path` = public app path, host-only, `SessionExpiry`).
      *(Landed with Stage 2's cookie-scheme wiring; verified by the Stage 3 ticket-inspection
      test: claims-only, `sub` preserved.)*
- [x] **T3.2 — Refresh parking**: encrypted HttpOnly cookie (DataProtection), separate
      name (prefix per T0.2), `Path` = public app path; written at callback, deleted at
      logout. *(Design doc §3.5.)*
- [x] **T3.3 — Single-flight silent renewal middleware**: on expired session + valid
      parked refresh → **serialize per user** (in-flight lock keyed by user id) → refresh
      via ar-auth `/token` (one-time-use rotation! design doc §10.A) → re-issue session +
      parked refresh cookies → continue request invisibly. Concurrent 401s wait, never
      race. Expired/revoked refresh → fall through to 401/login redirect, delete the
      parked cookie.
- [x] **T3.4 — Tests**: parallel-expiry test (N concurrent requests, exactly 1 refresh
      round-trip observed at the stub `/token`), expired refresh → 401 + cookie cleanup,
      rotation writes new parked cookie.

**Stage 3 findings (recorded):**
- Implementation: `BffRefreshStore` (DataProtection parking, purpose
  `Ar.Auth.OpenId.AspNetCore.Bff.Refresh.v1`, 30-day cookie matching the server-side
  refresh window), `BffSessionRenewer` (single-flight + refresh), hooks wired in
  `AddArAuthBff` via `SaveTokens=true` → extract `refresh_token` in `OnTicketReceived` →
  strip every `.Token.*` property → park. Verified: tokens ARE in properties when
  `OnTicketReceived` fires, and stripping lands before `SignInAsync` bakes the ticket.
- Ticket-inspection test decrypts the session cookie with the app's own
  `CookieAuthenticationOptions.TicketDataFormat` (no DataProtection purpose guessing)
  and asserts no `refresh_token`/`access_token` ride the session cookie.
- Renewal lock is keyed by SHA-256 of the refresh token (not `sub`): concurrent tabs
  carry the identical token, so the token IS the right serialization key — different
  browsers' independent chains never block each other. Waiters that queued behind a
  completed renewal reuse its result (2-minute window) instead of burning the rotated
  token — this is what makes the parallel test pass with exactly 1 `/token` roundtrip.
- Renewal does NOT reuse `ArAuthClient.RefreshTokenAsync`: it makes its own `/token`
  call (endpoint from the warm OIDC discovery config) so it can distinguish 400/401
  (`invalid_grant` → definitive → delete parked cookie) from transient failures (keep
  the parked cookie, next request retries). `ArAuthClient` wraps both into
  `TokenValidationException` — not distinguishable.
- Renewed principal is rebuilt from a fully validated id_token (`JsonWebTokenHandler.
  ValidateTokenAsync`, issuer from metadata, audience = ClientId, signature against the
  warm `OpenIdConnectConfiguration.SigningKeys`) — mirrors the login principal. The
  refresh grant's id_token exists only when the `openid` scope is granted, which the BFF
  always requests; without it renewal fails soft → 401.
- Wilson (8.x) API notes: `JsonWebTokenHandler.ValidateToken` is obsolete →
  `ValidateTokenAsync`; `TokenValidationResult` exposes `ClaimsIdentity` (not
  `ClaimsPrincipal`); `OpenIdConnectConfiguration` exposes `SigningKeys` (not
  `JsonWebKeys`).
- Renewal triggers on any anonymous request with a parked cookie (Bearer-header requests
  exempt); authenticated requests never hit the auth server (test asserts
  `RefreshGrantCount == 0` after a normal authenticated call).
- Renewal is in-proc single-flight; multi-instance deployments would need a distributed
  lock — out of scope (single-instance topology), noted in `BffSessionRenewer`.
- The stub's `RefreshGrantCount` counts refresh round-trips (attempts, not successes) —
  that is the semantics the single-flight assertion needs.

## Stage 4 — CSRF signed double-submit layer (S)

*(Design doc §4, layer 3. Layers 1–2 already shipped: `SameSite=Lax`, `SessionCookieGuard`.)*

- [x] **T4.1 — Token issuance**: `XSRF-TOKEN` cookie at session establishment — random value
      + HMAC signature (DataProtection) so sibling-subdomain cookie-tossing cannot forge it;
      readable by JS by design, `Path` = public app path.
- [x] **T4.2 — Enforcement middleware**: cookie-authenticated unsafe methods
      (POST/PUT/PATCH/DELETE) must present `X-CSRF-Token` header matching the signed cookie
      → else 403. Safe methods exempt. Bearer-authenticated requests exempt.
- [x] **T4.3 — Option gate**: `Csrf` mode (on / off), default-on per design doc §9.
- [x] **T4.4 — Tests**: missing header 403, mismatched 403, valid passes, GET exempt,
      forged token value with invalid HMAC 403 (cookie-tossing simulation), Bearer exempt.

**Stage 4 findings (recorded):**
- Implementation: `BffCsrfTokenService` (purpose `…Bff.Csrf.v1`; cookie value is a
  DataProtection-signed random 256-bit blob — the SPA copies it verbatim into the header,
  so the signature is invisible to it). Enforcement lives in `ArAuthBffMiddleware` AFTER
  the renewal step: a POST that triggered silent renewal passes on its OLD still-signed
  token (request cookies, not response cookies, are compared).
- Header names: `X-CSRF-Token` (documented SPA contract), with `X-XSRF-TOKEN` accepted as
  an alias so Angular's native `$http` interceptor works unchanged.
- 403 (not 401) only on the authenticated-unsafe-mismatch path; anonymous unsafe requests
  stay 401 so the SPA's "session gone → login link" logic is not misled.
- Issuance points: OIDC callback (`OnTicketReceived`) and silent renewal (`IssueAsync`),
  both gated on `Csrf != Off`; lifetime = `SessionExpiry` (always renewed with the session).
- Cookie-tossing test: attacker-chosen cookie value + dutifully matching header →
  double-submit MATCHES but the signature check rejects → 403. This is precisely the
  scenario the signed variant (vs. plain double-submit) exists for.
- 8 tests in `BffStage4Tests`; suite now 67/67 on net8/net10, no warnings.

## Stage 5 — Extensibility surface (M) — ✅ done

*(Design doc §3.9 — virtual hooks + delegate events over one mechanism.)*

- [x] **T5.1 — `ArAuthHandler`** with five virtual methods around the Stage 2–4 pipeline:
      `OnLoginRedirectingAsync`, `OnAuthenticatedAsync` (pre-`SignInAsync` enrichment /
      reject), `OnRedirectingAsync`, `OnLogoutAsync`, `OnRenewedAsync`.
- [x] **T5.2 — Registration**: `AddArAuthBff(bff => …)` (default handler) and
      `AddArAuthBff<THandler>(bff => …)` (DI-resolved subclass, constructor injection
      supported).
- [x] **T5.3 — `BffEvents`** delegate surface mapping onto the same five hook points
      (`bff.Events.OnAuthenticatedAsync = ctx => …`) — was wired in Stage 1; now routed
      through the handler so both surfaces compose.
- [x] **T5.4 — Tests**: hook invocation order (login → authenticated → redirecting),
      principal enrichment lands in session (`/claims` endpoint added to the harness),
      `Reject()` aborts with login redirect + no session, subclass DI resolution
      (extra ctor dep), event + subclass hooks compose via `base` call, renewal and
      logout hooks fire with the principal. 5 tests in `BffStage5Tests`.

**Findings (Stage 5):**

- **Interpretation of "base owns security work"**: the safer architecture kept from
  Stages 2–4 — security-critical work (state, PKCE, correlation, cookie issuance, CSRF)
  lives in the pipeline components and ALWAYS runs; the virtuals are pure hook points
  whose base implementations fire the `BffEvents` delegate. Overriding a hook cannot
  skip authentication machinery; NOT calling `base` only opts out of the delegate of
  the same name. Strictly fewer foot-guns than making virtuals own the base work.
- **Landing-URL plumbing (the one real trap)**: on the callback the OIDC handler does
  NOT restore `AuthenticationProperties.RedirectUri` — it is empty in
  `OnTicketReceived`. The validated landing URL rides in `TicketReceivedContext.ReturnUri`,
  and the handler redirects to that member after the event. Consequences:
  (a) seeding `BffAuthenticatedContext`/`BffRedirectContext` must read
  `ctx.ReturnUri ?? properties.RedirectUri`; (b) the (re-sanitized) result must be
  written back to `ctx.ReturnUri` or the redirecting hook's adjustment silently
  no-ops. The pre-Stage-5 code only passed the old round-trip test by luck: its
  `properties.RedirectUri` write was never read, and the untouched `ctx.ReturnUri`
  carried the URL.
- `OnRedirectingAsync` timing: fires in `OnTicketReceived` after refresh parking +
  XSRF issuance, immediately before `SignInAsync` + the final 302 — "last hook of the
  login flow". Cookie staging is done; the session ticket itself is issued by the
  framework right after. Doc comments on `BffEvents`/`ArAuthHandler` say exactly this.
- Harness: `BffTestApp.StartAsync` gained optional `configureServices` (extra DI
  registrations) and `configureAuth` (custom `AddArAuthBff<THandler>` wiring) params,
  plus an authorized `/claims` endpoint returning the principal's claims — enrichment
  assertions no longer infer from `sub` alone.
- Suite: 72/72 on net8/net10, build clean, no warnings.

## Stage 6 — Policy-scheme integration (S) — ✅ done

- [x] **T6.1 — Scheme composition**: the BFF installs its own policy scheme
      (`BffConstants.AuthScheme`, "ArAuth.Bff.Policy") as the default authenticate
      scheme, forwarding per request: **Bearer header → app session cookie →**
      (only when `AllowSessionCookie`) **auth-server session cookie handler**.
      Challenge stays Bearer-compatible (`DefaultChallengeScheme` untouched).
- [x] **T6.2 — Precedence tests**: Bearer wins over a valid session cookie (distinct
      identities: cookie user-42 vs. token user-77, asserted via `/claims`), session
      cookie authenticates with no header, neither → 401 with `WWW-Authenticate: Bearer`,
      auth-server cookie still authenticates with the BFF on (and Bearer beats it too).
      4 tests in `BffStage6Tests`. Existing `AllowSessionCookie`-off-BFF behavior is
      untouched by construction (the composition scheme is registered inside
      `AddArAuthBffCore` only) — full suite green as the regression net.

**Findings (Stage 6):**

- **Why a BFF-owned scheme name** (instead of re-pointing `ArAuthPolicyScheme` /
  "ArAuthSmart"): that scheme is registered by `AddArAuth` only when
  `AllowSessionCookie` is on, and duplicate scheme-name registration throws at
  provider build. The BFF extension cannot know `AllowSessionCookie` at registration
  time (the `ArAuthOptions` instance is captured inside `AddArAuth`), so reusing the
  name would need conditional registration — fragile. The new name sidesteps it; when
  both are registered ("ArAuthSmart" + BFF policy), `DefaultAuthenticateScheme` points
  at the BFF policy and the legacy one is simply never selected.
- The precedence chain is a **presence** chain, not a validation chain: an expired
  app cookie still forwards to the app session scheme (anonymous → silent renewal /
  401), it does NOT fall through to the auth-server cookie. That is deliberate —
  with a parked refresh the renewal path is strictly better than the shared cookie.
- The policy scheme is an `IAuthenticationRequestHandler`: at the OIDC callback
  (fresh browser, no cookies/headers) its forwarded `HandleRequestAsync` lands on
  the no-op session handler and returns false, so UseAuthentication's scheme
  iteration still reaches the OIDC scheme for the callback — verified by the existing
  round-trip suite staying green.
- Claim-shape caveat surfaced by the tests: JwtBearer (`MapInboundClaims=true`
  default) and the legacy `ArAuthClient` handler rename `sub` →
  `ClaimTypes.NameIdentifier`; only the BFF OIDC path (`MapInboundClaims=false`)
  yields raw `sub`. `/me`'s `FindFirst("sub")` is therefore a BFF-session-only
  assertion; the Stage 6 tests assert Bearer/server-cookie identities via `/claims`
  by value. Not changed — the Bearer claim shape is the frozen cross-domain contract.
- Harness: `BffTestApp.StartAsync` gained `configureArAuth` (allows
  `AllowSessionCookie`/`CookieName` overrides); the stub gained `CreateAccessToken(sub)`
  and `CreateSessionToken(sub)` minted with its RSA key.
- Suite: 76/76 on net8/net10, build clean, no warnings.

## Stage 7 — Docs, sample, release (M) — ✅ done

- [x] **T7.1 — README** (`ar-auth-client-dotnet/README.md`): BFF is the headline
      same-domain integration (full section: flow, options, SPA contract, extensibility,
      DataProtection deployment box, local-dev/proxy box); session-cookie section
      retitled "Session-Cookie Fallback (Legacy Shared-Domain Cookie)" with a pointer
      to the BFF; packages table updated; CHANGELOG linked.
- [x] **T7.2 — Sample app**: `samples/BffSample` (net10.0, in the solution, not packed) —
      config-driven `AddArAuth` + `AddArAuthBff`, `/me` + `/submit`, and
      `wwwroot/index.html` implementing the exact SPA contract (links, boot probe, XSRF
      header wrapper). Smoke-tested: index 200, `/me` 401 anonymous, `/auth/login` 302.
- [x] **T7.3 — Plan/design doc sync**: `docs/cookie-auth-plan.md` §6 "Still to build" →
      built (table extended with per-stage rows); §8 index item 10 → built; §9.1 open
      question resolved (8 h sessions, CSRF default-on); §10.B all four items checked
      (folded into README, implemented, or documented); §10.C verified story recorded.
- [x] **T7.4 — Version bump + CHANGELOG**: `Directory.Build.props` 1.2.0 → 1.3.0; the two
      `-local` project overrides → 1.3.0-local (AspNetCore inherits 1.3.0 from props, as
      before); new `CHANGELOG.md` with a 1.3.0 entry covering the BFF (headline) and the
      session-cookie fallback, plus the deployment warning. Full solution build clean,
      no warnings; suite 76/76 on net8/net10. net9 runtime is not installed on this
      machine — not exercised locally (environmental, pre-existing note).

---

## Explicitly out of scope (tracked elsewhere)

| Item | Where |
|---|---|
| Management carve-out (backend cookie auth + DB role re-check + `[Authorize]` migration) | `docs/cookie-auth-plan.md` §7 |
| Python cookie-validation port (if a same-domain *python* API ever happens) | `docs/cookie-auth-plan.md` §6 note |
| `end_session_endpoint` on the auth server | Triggered only by SSO auto-login (§10.A) |
| Cross-site cookie support (`SameSite=None` Phase 2) | Rejected unless a real Safari-proof case appears (§7) |
| Session → access-token minting endpoint for browser-side user-token calls | Open question §9.2 |
| Client registration for the first real app | Ops task at app-launch, not code |

## Sequencing notes

- Stage 4 can proceed **in parallel** with Stage 3 (different files, both depend on 2).
- Stages 2 and 3 each end with integration tests via the T0.1 harness — do not start 2
  without the harness decision.
- If T0.2's cookie naming lands as "derive prefix from CookiePath", revisit Stage 1 files
  once, before Stage 2 starts — it threads through every cookie write.
- Single-flight (T3.3) is not an optimization — ar-auth refresh tokens are one-time-use;
  without it, parallel expiry reliably logs users out.
