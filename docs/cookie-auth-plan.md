# Design: Session Cookies & Same-Domain App Authentication

Consolidated decision record for cookie-based authentication across the ar-auth ecosystem.
Supersedes all earlier drafts in this file (history compressed into the decision rationale).

---

## 1. The fundamental split: two app topologies

The driving constraint discovered early in this work: **cookies belong to the domain that set
them.** The auth server's cookie can never reach an API on a different domain — so cookie auth
is only viable for same-site apps. This yields two clean classes of app:

| | **Cross-domain apps** (the majority today) | **Same-domain apps** (the next app) |
|---|---|---|
| Topology | SPA on `vendor-app.com`, API elsewhere | SPA + API under one host/path, e.g. `apps.adolfrey.com/application1/` + `/application1/api` |
| Credential | Bearer access token in JS (`ar-auth-client`) | **Session cookie only — nothing in JS** |
| Login | Redirect flow, SPA handles callback + code exchange | **BFF**: backend processes the callback (see §3) |
| Frontend library | `ar-auth-client` (kept, scope frozen) | **None needed** |
| Renewal | SPA refresh-token grant (custom, bypasses `prompt=none` iframe) | Server-side silent renewal from parked refresh token |

---

## 2. Backend stays a stateless token issuer (decided)

- The auth server will **not** honor cookies on its own API. OAuth-facing endpoints
  (`/token`, `/authorize`, discovery, JWKS, login callbacks) accept Bearer only.
- Honoring a session cookie is not inherently stateful (it's a self-contained JWT), but the
  role boundary stays clean: the auth server issues and validates; resource servers accept.
- Only backend change made: **`AppConfig.Jwt.SessionCookieDomain`** → `AuthHelper.SessionCookieDomain`
  → `Domain` attribute on `ar_auth_session` (set + clear). Null = host-only (default).
  This exists for the sibling-subdomain case (e.g. `Domain=.adolfrey.com`); it does **not**
  apply to the BFF topology (§3), where the app host sets its own cookie.
- Known dead weight: `ar_auth_session` is set on every login but read by nothing
  (`GetSessionUserId` has zero callers). Left as-is until the management carve-out (§7).

Session JWT facts: `type=session`, audience = Issuer, 30-day expiry, claims `sub`/`email`/`name`
— **no roles, no scopes**. A cookie principal can therefore never pass `Roles`/`scope`
requirements — deliberate: *cookie = who the user is; Bearer = what they may do.*

**Bearer survives in every topology — only its location changes.** The rule above is a
privilege boundary, not a requirement that the browser hold a token:

- Auth server API: Bearer only, always.
- Cross-domain apps: Bearer **in JS** (the SPA holds and sends it) — `ar-auth-client`'s role.
- Same-domain BFF apps: the browser never sees a Bearer. The access/refresh tokens from the
  code exchange live **server-side** (parked encrypted cookie, §3.5); the app API's own
  calls run on the session cookie, and any auth-server-authorized privilege (scope/role)
  is exercised server-to-server with the access token — Bearer, just not browser-borne.

---

## 3. Same-domain BFF design (the new centerpiece)

Target topology (per-app, repeatable for each application on the host):

```
SPA:  https://apps.adolfrey.com/application1/
API:  https://apps.adolfrey.com/application1/api/*
```

### 3.1 Why the auth server cannot set the app's cookie

`auth2.adolfrey.com` responses can only set cookies for `auth2.adolfrey.com` or the parent
`.adolfrey.com` — browsers **reject** `Domain=apps.adolfrey.com` set from a sibling host,
and the auth server doesn't know app-specific paths anyway. Therefore the **app host sets
its own session cookie**, and the BFF flow (below) is what makes that possible at login time.

### 3.2 Cookie scoping (per-app isolation)

```
session cookie: HttpOnly, Secure, SameSite=Lax, Path=/application1/, Domain unset (host-only)
```

- `Path=/application1/` means app2 (`/application2/`) never receives app1's cookie —
  per-app least privilege on a shared host. This resolves the "one cookie, all subdomains"
  blast-radius concern that killed the shared `Domain=.adolfrey.com` approach for this use case.
- Host-only Domain needs **no `Domain` attribute at all** — the browser default is the issuing host.
- `Lax` suffices: SPA ↔ API is same-*site* (same registrable domain), and the login callback
  arrives as a top-level navigation (which Lax allows).

### 3.3 The flow (code grant, backend-processed callback)

```
1. SPA:          window.location = /application1/api/auth/login      (just a link)
2. API:          generate state + PKCE verifier
                 Set-Cookie: correlation cookie { state, verifier, returnUrl }
                             signed/encrypted (DataProtection), HttpOnly, Path=/application1/, ~5 min
                 302 → auth2.adolfrey.com/authorize?
                       redirect_uri=https://apps.adolfrey.com/application1/api/auth/callback
                       &scope=… &state=… &code_challenge=…&code_challenge_method=S256
3. Auth server:  user authenticates (password / passkey / Google / Telegram — unchanged)
4. Auth server:  302 → /application1/api/auth/callback?code=…&state=…
5. API callback: validate state vs correlation cookie (else reject: login CSRF)
                 delete correlation cookie (single-use)
                 exchange code (library: ExchangeCodeAsync)
                 mint session → SignInAsync → Set-Cookie (session cookie, §3.2)
                 park refresh token in its own encrypted HttpOnly cookie (§3.5)
                 302 → returnUrl
6. SPA boot:     GET /application1/api/me (no Bearer) → 200 via cookie → logged in
7. All API calls: cookie only. No Authorization header. Nothing in JS.
```

**Auth server changes required: none.** The code flow, `state` pass-through, and
`redirect_uri` binding already exist. Just register the client with
`redirect_uri = https://apps.adolfrey.com/application1/api/auth/callback`.

### 3.4 Client registration: no secrets needed (decided)

The app is registered as a **public client**: no `client_secret` anywhere — not in the SPA
(it never touches tokens), not in the backend (doesn't need one). Security binding:
- code bound to `redirect_uri` (server-side callback on the app's own origin), and
- PKCE, with the verifier generated **server-side** and parked in the correlation cookie —
  the SPA never handles it.

The auth server already enforces exactly this tiering (`TokenFunction.cs`): public client
(no secrets on record) ⇒ PKCE required; confidential ⇒ secret required. Alternative, if
secret management is ever preferred: register confidential + `client_secret`
(`ArAuthOptions.ClientSecret` / `ExchangeCodeAsync` already support body and Basic forms).
PKCE is sent regardless as defense in depth.

### 3.5 Refresh token parking (silent renewal)

The SPA holds no tokens, so session expiry must be survivable without a login redirect:

- The backend parks the refresh token in an **encrypted HttpOnly cookie** (DataProtection,
  `Path=/application1/`, separate name from the session cookie).
- When the session cookie expires/absent but the refresh cookie is valid, the API's
  middleware silently refreshes, re-issues both cookies, and continues — invisible to the
  user and to SPA code.
- **Renewal must be single-flight**: ar-auth refresh tokens are one-time-use (rotated on
  each use), so concurrent 401-triggered renewals must serialize per user (others wait for
  the in-flight refresh to complete) or they will race and spuriously log the user out.
- Alternative (rejected for now): server-side store — adds state; encrypted cookie is
  stateless and consistent with everything else here.

### 3.6 State handling — the one hard rule

In BFF, **the SPA never sees the callback**, so state generation/ validation must live in
the backend (SPA-generated state would be unvalidatable → login CSRF + code injection).

Correlation cookie rules (replicating what ASP.NET Core's OIDC handler does internally):
- Backend-generated `state` + PKCE verifier + validated `returnUrl`, DataProtection-signed.
- Short TTL (~5 min), single-use (deleted on read), HttpOnly, `Path=/application1/`.
- `returnUrl` must be validated as a local relative path before storage (open-redirect guard).
- Multi-tab edge case: parallel `/auth/login` calls collide on one cookie name — use a
  random per-attempt suffix, or accept last-write-wins (older tab's callback fails state
  check and retries).

### 3.6.1 Cookie inventory (frequent point of confusion)

| Cookie | Held by | Contents | Purpose |
|---|---|---|---|
| Session cookie | App host | App-local **encrypted ticket** (DataProtection via `SignInAsync`) — claims, **not** a token | "Who is this user" for the app API |
| Refresh cookie | App host | **Encrypted refresh token** (parked; separate name, same path) | Silent server-side renewal (§3.5) |
| `ar_auth_session` | Auth server | Auth-server **session JWT** (`type=session`) | Auth server login flow / management carve-out (§7) |
| `XSRF-TOKEN` | App host | Random value + HMAC signature (readable by JS, by design) | CSRF double-submit (§4) |

The **access token** is never in a cookie: BFF apps hold it server-side only; cross-domain
apps hold it in JS/localStorage. Rationale: (1) lifetime mismatch — access tokens are
short-lived, sessions are not; (2) privilege coupling — the access token carries scopes/
roles, and putting it in a browser-held cookie would let privileges ride every request
automatically, the exact problem this design avoids. (The session cookie *behaves* like a
bearer credential in the HTTP sense — possession authenticates — but its value is the
app's own ticket, not a token.)

### 3.7 Implementation basis: `AddOpenIdConnect`, not hand-rolled middleware

The BFF feature in `Ar.Auth.OpenId.AspNetCore` should be **`AddArAuthBff`** — a thin wrapper
configuring the built-in `AddOpenIdConnect()` handler (correlation cookies, state/nonce
validation, PKCE, code exchange, cookie-based session) with:
- authority = the ar-auth server, PKCE forced, public-client mode,
- session + correlation cookie paths, host-only Domain,
- silent renewal via the parked refresh token cookie,
- integration with the existing policy scheme (Bearer → cookie → …).

Battle-tested framework machinery beats reimplementing correlation/state logic.
(The Python port plays the same role with **AuthLib**'s Starlette client — see the
Python table in §6.)

### 3.8 `AddArAuthBff` API shape (decided)

The login/callback/logout endpoints are **auto-created**: the middleware intercepts those
paths in the pipeline (remote-auth style, like `signin-oidc`). App code writes no handlers
for them, and they bypass `[Authorize]` by construction.

```csharp
.AddArAuthBff(bff =>
{
    // Paths the app's pipeline responds on (internal — after a reverse proxy strips its prefix)
    bff.LoginPath    = "/auth/login";      // defaults
    bff.CallbackPath = "/auth/callback";
    bff.LogoutPath   = "/auth/logout";

    // What the outside world sees (browser + auth server perspective). Needed when the
    // proxy rewrites/strips a path prefix: public URL /app/api/auth/callback, app sees /auth/callback.
    bff.PublicBaseUrl = "https://apps.adolfrey.com/app/api";

    // Derived: redirect_uri = PublicBaseUrl + CallbackPath
    //          cookie Path    = public base path (browser-visible), overridable
    //          session expiry, CSRF mode, refresh parking — defaults per §3.5 / §4
});
```

Path duality — each path has an internal identity (route matching) and a public identity:

| Uses internal path | Uses public path |
|---|---|
| Route the middleware listens on | `redirect_uri` sent to `/authorize` (must match client registration exactly) |
| | Cookie `Path` — cookies are matched against the **browser-visible** path; an internal-path cookie would never be sent back after prefix stripping |
| | Post-login `returnUrl` redirects, end-session redirects |

Alternative topology worth supporting: if the proxy sends `X-Forwarded-Prefix` (or the app
calls `UsePathBase`), internal == public and `PublicBaseUrl` can be derived instead of
configured. Rule: derive public from forwarded headers/`UsePathBase` when present, else
require explicit `PublicBaseUrl` when the proxy strips the prefix silently.

### 3.9 Extensibility: handler subclassing + events (decided)

`AddArAuthBff` supports two extension surfaces over the same hook set:

```csharp
.AddArAuthBff(bff => { … });                  // default handler
.AddArAuthBff<MyAuthHandler>(bff => { … });   // subclassed handler (DI-resolved)
bff.Events.OnAuthenticatedAsync = ctx => …;   // or delegate events, no class needed
```

Virtual surface on `ArAuthHandler` (granular hooks around security-critical steps —
overrides compose via `base`, they do not replace the pipeline):

| Hook | When | Base does |
|---|---|---|
| `OnLoginRedirectingAsync` | SPA hit login, before 302 to `/authorize` | state + PKCE + correlation cookie, then redirect (hook may add extra authorize params) |
| `OnAuthenticatedAsync` | code exchanged + validated, before `SignInAsync` | session + refresh cookie issuance (hook may enrich principal, reject, adjust returnUrl) |
| `OnRedirectingAsync` | before post-login redirect | final `returnUrl` redirect |
| `OnLogoutAsync` | around end-session | local cookie cleanup + end-session redirect |
| `OnRenewedAsync` | silent renewal (§3.5) | re-issued session/refresh cookies |

Delegates map onto `OpenIdConnectEvents` (`RedirectToLoginProvider`, `TicketReceived`,
`RemoteFailure`); the virtual methods are typed wrappers around the same pipeline points.

Design rule: **base implementations own everything security-critical** (state, PKCE,
correlation, cookie issuance, CSRF checks). Virtuals are observability, enrichment, and
parameterization points — an override that skips `base` deliberately opts out of the
secure defaults. Handler subclasses are DI-resolved (can inject `IUserService` etc.).

---

## 4. CSRF protection ("csrfp") — three layers

In BFF mode every API call is cookie-authenticated (no Bearer to win precedence), so CSRF
matters and is layered:

| Layer | Mechanism | Status |
|---|---|---|
| **1. `SameSite=Lax`** | Blocks cross-site attacker POSTs from carrying the cookie. Gaps: top-level GET navigations (keep GETs safe) and **same-site sibling subdomains** — `fetch(…, {credentials:'include', mode:'no-cors'})` from `evil.adolfrey.com` executes against the API with the cookie attached (CORS blocks reading the response, not the state change). Lax alone is insufficient. | ✅ In place (cookie policy) |
| **2. Origin check** | On unsafe methods, require `Origin`/`Referer` to be same-origin or allow-listed; missing `Origin` allowed on GET/HEAD/OPTIONS, rejected on POST/PUT/PATCH/DELETE. Kills the sibling-subdomain case. | ✅ Built — `SessionCookieGuard`, wired into both `ArAuthSessionHandler` and `ArAuthMiddleware` |
| **3. Signed double-submit token** | Non-HttpOnly `XSRF-TOKEN` cookie (`Path=/application1/`) set at session establishment; middleware requires header `X-CSRF-Token` == cookie value on cookie-authenticated unsafe requests. **Signed variant** (HMAC via DataProtection) closes *cookie tossing*: a sibling subdomain can plant `Domain=.adolfrey.com` cookies that this host receives — it could set a matching plain token value, but cannot produce a valid signature. Stateless — no server-side store. | ✅ Built — default-on in `AddArAuthBff` / `add_ar_auth_bff` |

SPA cost for layer 3: a three-line fetch wrapper (read `XSRF-TOKEN` cookie → send
`X-CSRF-Token` header). Angular's `$http` does this natively (`XSRF-TOKEN`/`X-XSRF-TOKEN`
convention); a small axios/fetch interceptor for React.

Note: Bearer-authenticated requests are immune to CSRF (attacker JS cannot set the
`Authorization` header cross-site) — layers 2–3 apply to the cookie path only.

---

## 5. SPA contract (same-domain apps)

The entire auth surface of the SPA:

```tsx
// sign in / sign out are plain navigations — no library, no tokens, no PKCE, no state
<a href="/application1/api/auth/login?returnUrl=/">Sign in</a>
<a href="/application1/api/auth/logout?returnUrl=/">Sign out</a>

// boot: ask the server whether a session exists
const res = await fetch("/application1/api/me");   // no Bearer → cookie decides
setLoggedIn(res.ok);

// privileged call hits 401? → one full login redirect to mint fresh authorization
```

Rules:
- **No `credentials: 'include'`** — same-origin requests carry cookies by default.
- **Never read the session cookie** — it's HttpOnly by design; only `XSRF-TOKEN` is readable.
- Token-renewal code: none — renewal is server-side (§3.5).
- The SDK owns the login/callback/logout routes (§3.8); the app adds only one trivial
  endpoint: `GET me` (`[Authorize]`, returns identity).

`ar-auth-client` (JS) keeps its current role, **scope frozen**: cross-domain SPAs only —
Bearer + custom refresh-token grant, unchanged. It stops being a dependency of same-domain apps.

---

## 6. Already implemented (this repo)

| Piece | Where | Notes |
|---|---|---|
| `ArAuthClient.ValidateSessionTokenAsync` | core `Ar.Auth.OpenId` | Session JWT validation via existing JWKS path (`audience = authority` + `type == "session"`) |
| `SessionCookieGuard` | core `Ar.Auth.OpenId` | CSRF origin rules (layer 2); shared by both packages; unit-tested (26/26 pass on net8/net10) |
| `ArAuthOptions.AllowSessionCookie / CookieName / AllowedCookieOrigins` | core `Ar.Auth.OpenId` | Opt-in; default **off** — zero behavior change for existing users |
| `ArAuthSessionHandler` + `ArAuthPolicyScheme` | `Ar.Auth.OpenId.AspNetCore` | Policy scheme: Bearer wins when `Authorization` present, else session cookie; challenges stay `WWW-Authenticate: Bearer` |
| Cookie fallback in `ArAuthMiddleware` | `Ar.Auth.OpenId.AzureFunctions` | Same precedence + shared roles/scopes checks; all 401/403 messages preserved |
| `SessionCookieDomain` config | backend | `AppConfig.Jwt.SessionCookieDomain` → `AuthHelper` → `Domain` attribute on set/clear |
| **`AddArAuthBff`** (§3.7/§3.8) | `Ar.Auth.OpenId.AspNetCore` | `ArAuthBffExtensions` + `ArAuthBffMiddleware` — login/logout/callback routes, OIDC (code + PKCE) on `AddOpenIdConnect`, app-local cookie issuance, path-duality guard. Stages 2 |
| **Refresh parking + silent renewal** (§3.5) | `Ar.Auth.OpenId.AspNetCore` | `BffRefreshStore` (DataProtection parking) + `BffSessionRenewer` (single-flight per chain, SHA-256 keyed, warm discovery; tickets carry claims only — tokens stripped). Stage 3 |
| **Signed double-submit CSRF** (§4 layer 3) | `Ar.Auth.OpenId.AspNetCore` | `BffCsrfTokenService` — HMAC-signed `XSRF-TOKEN` cookie echoed via `X-CSRF-Token` (`X-XSRF-TOKEN` alias), default-on, issued at callback + renewal. Stage 4 |
| **Extensibility surface** (§3.9) | `Ar.Auth.OpenId.AspNetCore` | `ArAuthHandler` (five virtuals) + `BffEvents` delegates — compose via `base`; base work (state/PKCE/cookies/CSRF) lives in the pipeline and cannot be skipped. Stage 5 |
| **Scheme composition** | `Ar.Auth.OpenId.AspNetCore` | `ArAuth.Bff.Policy` default scheme: Bearer header → app session cookie → (opt-in) auth-server session handler. Stage 6 |
| Test harness (T0.1) | `tests/Ar.Auth.OpenId.Tests` | In-proc Kestrel `StubOidcServer` (RSA JWKS, PKCE S256, rotating refresh) + `BffTestApp`; 76 tests green on net8/net10 |
| README + sample | `ar-auth-client-dotnet` | BFF headline section (SPA contract, deployment box), demoted session-cookie section; runnable `samples/BffSample` |

The .NET stack was staged per `docs/bff-implementation-plan.md` (Stages 0–7, findings
recorded there); the consuming app provides the `GET me` boot probe per §5.

**Python port (ar-auth-client-python 0.6.0)** — same architecture, framework-idiomatic
surface, staged per `docs/python-bff-implementation-plan.md` (Stages 0–7, findings there):

| Piece | Where | Notes |
|---|---|---|
| `ArAuthClient.verify_session_token` | `src/ar_auth/client.py` | Session JWT validation via the existing JWKS path (audience = authority + `type == "session"`) |
| `SessionCookieGuard` | `src/ar_auth/session_cookie_guard.py` | CSRF origin rules shared by all integrations; opt-in `allow_session_cookie` on `ArAuthBearer` / `requires_auth` / `requires_auth_azure` |
| **`add_ar_auth_bff`** (§3.7/§3.8) | `src/ar_auth/bff.py` | AuthLib owns state/PKCE/correlation (scoped `SessionMiddleware` correlation cookie, 10-min TTL); itsdangerous claims-only session ticket; explicit required secret (no default key ring) |
| Refresh parking + silent renewal (§3.5) | `src/ar_auth/bff.py` | `_RefreshStore` (Fernet-parked cookie) + per-chain single-flight renewal + 2-min reuse window |
| Signed double-submit CSRF (§4 layer 3) | `src/ar_auth/bff.py` | `_CsrfTokenService` — default-on, `BffCsrfMode.OFF` opt-out; `X-CSRF-Token` (`X-XSRF-TOKEN` alias) |
| Extensibility surface (§3.9) | `src/ar_auth/bff.py` | Five hooks: `ArAuthBff` subclass (`add_ar_auth_bff(..., bff=)`) or `BffEvents` delegates; compose via `super()`; base work cannot be skipped |
| Precedence composition | `src/ar_auth/bff.py` | `Depends(bff.auth)`: Bearer header → app session cookie → (opt-in) auth-server session cookie; challenges stay `WWW-Authenticate: Bearer` |
| Test harness | `tests/` | Real-socket stub OIDC provider + uvicorn app-under-test (port of the .NET harness); 124 tests green |
| README + sample | `ar-auth-client-python` | BFF headline (SPA contract, secret-provisioning box), demoted session-cookie section; `samples/bff_sample` (same SPA contract as the .NET sample) |

---

## 7. Deferred / future work

### Management carve-out (planned, not started)

Cookie auth for the backend's own **management endpoints** — the `frontend/` admin console
(`frontend/`, `/admin` routes) is same-origin with the backend API.

- Scope: honor `ar_auth_session` on `AdminUserEndpoints`, `AdminClientEndpoints`,
  `UserManagement` (maybe `Profile`/`PAT`); OAuth-facing endpoints untouched.
- CSRF: same-origin `Origin` check only (first-party SPA — no registry lookup needed).
- Privileges (decided, Option A): cookie identifies the user (`sub`); admin endpoints
  **re-check roles from the DB per request** via `IUserService`. Fully revocable — demoting
  an admin takes effect on their next request; one cheap DB read per admin call.
  (Rejected Option B: enriching `GenerateSessionToken` with `role` claims — privilege
  changes wouldn't take effect until re-login, up to 30 days.)
- Rationale: keeps admin access tokens out of localStorage (XSS hygiene) while preserving
  the backend's stateless-token-issuer role. Note the standard `[Authorize]` /
  `AddAuthentication` migration of the backend (isolated worker has the ASP.NET Core
  integration via `ConfigureFunctionsWebApplication`) is part of this future work.
- Prerequisites: none blocking; independent of everything above.

### Cross-site cookie support (Phase 2 — only if ever required)

`SameSite=None` + per-client allow-list + Safari fallback guidance. Explicitly rejected for
now: third-party cookies are unreliable in Safari regardless; cross-domain apps use Bearer.

---

## 8. Resolved decisions (index)

1. **Backend accepts Bearer only** — stateless token issuer; no cookie-honoring API.
2. **Cookie = identity, Bearer = authorization** — session JWT carries no roles/scopes by design.
3. **Same-site only** — cross-domain apps use Bearer; `SameSite=Lax` kept (set at issuance).
4. **Opt-in per app** — `AllowSessionCookie` on the resource server; roles/scope enforcement unchanged.
5. **Same-domain apps use the BFF pattern** — backend-processed callback, app-hosted
   path-scoped cookie, nothing in JS.
6. **Public client registration** — PKCE only, verifier generated server-side; secret optional.
7. **State via backend correlation cookie** — signed, short-TTL, single-use, local-validated `returnUrl`.
8. **BFF built on `AddOpenIdConnect`** (`AddArAuthBff`), not hand-rolled middleware.
9. **Renewal via parked encrypted refresh cookie** — silent, server-side, stateless.
10. **CSRF = Lax + Origin check (built) + signed double-submit token (built, default-on).**
11. **SPA client (JS) frozen** — cross-domain Bearer role only; same-domain apps need no JS library.
12. **Management carve-out** — cookie + DB role re-check per request; deferred with design settled.

## 9. Open questions

1. ~~`AddArAuthBff` defaults~~ — **resolved**: 8 h app sessions (`BffOptions.SessionExpiry`),
   silently renewable while the refresh chain lives; CSRF default-on
   (`BffCsrfMode.SignedDoubleSubmit`).
2. Does any same-domain app need to call third-party APIs with the *user's* token? If yes,
   that app needs a Bearer minting path (small endpoint exchanging session → access token).
3. Management carve-out scheduling (backend `[Authorize]` migration included).

## 10. Pre-build checklist (close before/while building `AddArAuthBff`)

### A. Verify auth-server capabilities — ✅ VERIFIED (no backend changes needed)

- [x] **Refresh tokens for public clients** — confirmed: the authorization-code grant issues
      `refresh_token` unconditionally (`TokenFunction.cs`); the secret check only applies to
      confidential-client callers. §3.5 stands as designed.
- [x] **Refresh token rotation** — confirmed: `RotateRefreshTokenAsync` deletes the old token
      (one-time use) and mints a fresh 30-day expiry → **sliding 30-day window** while the
      user returns at least once per 30 days. Consequence for the client library: renewal
      **must be single-flight** (concurrent 401-triggered refreshes race; the loser's token
      is already revoked → spurious logout). Client-library work only.
- [x] **`end_session_endpoint`** — absent, and acceptable: nothing reads `ar_auth_session`
      today, so there is no SSO auto-login to escape; BFF logout = app-local cookie cleanup
      and that is complete, honest semantics. Revisit only when SSO auto-login appears
      (e.g. the management carve-out) — *that* would be the trigger for a backend addition.

Remaining backend task is **configuration, not code**: register the next app's client
(public, no secret, `redirect_uri = <PublicBaseUrl>/auth/callback`, scopes) when the app
is ready.

### B. Design details to fold into §3 / README before implementation — ✅ folded into README (T7.1)

- [x] **DataProtection key persistence** (§3 deployment requirement): multi-instance/
      restart apps MUST share the key ring (Key Vault / blob / Redis). In-memory keys =
      every restart silently invalidates all sessions. This is the top operational
      foot-gun of the BFF. → README "Deployment" warning box + sample-app comment.
- [x] **Callback idempotency**: Back-button/refresh on the callback after the code was
      consumed → `invalid_grant` → graceful redirect to `LoginPath`, never a 500
      (`OnRemoteFailure`/`OnAuthenticationFailed` + consumed-code test).
- [x] **Cookie name collisions across multiple apps on one host**: solved by the
      per-app prefix derived from the effective cookie path (`/application1/` →
      `application1.`; `CookieNamePrefix` overrides) applied to ALL BFF cookies —
      documented on `BffOptions` and in the README options note.
- [x] **Local dev note**: cookies are `Secure` on https (`SameAsRequest`), so plain-http
      dev only works against plain-http mock authorities; mkcert + `--urls https://…`
      guidance in the README "Local dev & proxies" box. No production escape hatch —
      http authorities are the only allowance (local mocks).

### C. Verification story — ✅ decided & built (T0.1)

- [x] How to test the BFF: in-proc Kestrel **stub OIDC provider** (`StubOidcServer`:
      RSA JWKS, PKCE S256 verification, rotating one-time-use refresh tokens with
      burn-on-read) + **`BffTestApp`** app-under-test, shipped inside the test project
      — integration suites for Stages 2–6 (76 tests, green on net8/net10). The runnable
      `samples/BffSample` doubles as the manual harness for the real auth server.
