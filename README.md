# Atlas Rig - OAuth 2.0 Integration Guide

Welcome to the **Atlas Rig** integration guide. This document explains how third-party and internal applications can connect to the Atlas Rig system to authenticate users via the **Authorization Code Flow with PKCE**.

## 🚀 Overview

Atlas Rig Auth acts as a central Identity Provider (IdP) following OAuth 2.0 and OpenID Connect (OIDC) standards. 

**Base URL**: `https://auth.adolfrey.com`

### Required Endpoints

| Endpoint | Path | Method | Description |
|---|---|---|---|
| **Discovery** | `/api/.well-known/openid-configuration` | GET | Returns the OIDC metadata document. |
| **Authorization** | `/api/authorize` | GET | Initiates the login flow and redirects the user to the login UI. |
| **Token** | `/api/token` | POST | Exchanges an authorization code for an ID token, access token, and refresh token. |
| **UserInfo** | `/api/userinfo` | GET/POST | Returns profile information about the authenticated user. |
| **JWKS** | `/.well-known/jwks.json` | GET | JSON Web Key Set used to verify the signature of JWTs. |

---

## 🛠️ Method 1: Using an OIDC Library (Recommended)

The easiest way to integrate is by using a standard OIDC library, which handles the complex tasks of state management, PKCE generation, and token rotation automatically.

For React/TypeScript applications, we recommend `oidc-client-ts`.

### 1. Install the Library
```bash
npm install oidc-client-ts
```

### 2. Configure the UserManager

```typescript
import { UserManager, WebStorageStateStore } from 'oidc-client-ts';

const userManager = new UserManager({
    authority: 'https://auth.adolfrey.com/api', // Discovery URL base
    client_id: 'your-client-id',
    redirect_uri: window.location.origin + '/auth/callback',
    popup_redirect_uri: window.location.origin + '/auth/popup-callback',
    response_type: 'code',
    scope: 'openid profile email', // Add other scopes as needed
    userStore: new WebStorageStateStore({ store: window.sessionStorage }),
    monitorSession: false // Turn off if iframe session monitoring isn't fully supported
});
```

### 3. Initiate Login (Redirect Flow)
This will redirect the user entirely to the auth domain and back.
```typescript
const login = () => {
    userManager.signinRedirect();
};
```

### 4. Handle Redirect Callback
On the route corresponding to your `redirect_uri` (e.g., `/auth/callback`):
```typescript
const handleCallback = async () => {
    try {
        const user = await userManager.signinRedirectCallback();
        console.log("Logged in user:", user);
        // Redirect to dashboard
    } catch (e) {
        console.error("Login failed", e);
    }
};
```

### 5. Initiate Login (Popup Flow)
Alternatively, you can open a popup window for login, keeping your main application state intact.
```typescript
const loginWithPopup = async () => {
    try {
        const user = await userManager.signinPopup();
        console.log("Logged in user:", user);
    } catch (e) {
        console.error("Popup login failed", e);
    }
};
```

### 6. Handle Popup Callback
On the route corresponding to your `popup_redirect_uri` (e.g., `/auth/popup-callback`):
```typescript
// The library handles this automatically when called on the popup page
userManager.signinPopupCallback();
```

---

## 📦 Method 3: Using Atlas Rig Auth Client (Highly Recommended)

For the most streamlined experience in React/TypeScript applications, use our official wrapper library which provides a `useAuth` hook and simplified state management.

### 1. Wrap your App
```tsx
import { AuthProvider } from 'ar-auth-client';

const config = {
  authority: 'https://auth.adolfrey.com',
  clientId: 'my-app-id',
  redirectUri: window.location.origin + '/callback',
  scope: 'openid profile email'
};

root.render(
  <AuthProvider config={config}>
    <App />
  </AuthProvider>
);
```

### 2. Use the Context
```tsx
import { useAuth } from 'ar-auth-client';

export const Navbar = () => {
  const { user, login, logout, loginState, isLoading } = useAuth();

  if (isLoading) return <span>...</span>;

  return user ? (
    <div>
      <span>{user.name}</span>
      <button onClick={logout}>Logout</button>
    </div>
  ) : (
    <button onClick={() => login({ state: { from: 'navbar' } })}>Login</button>
  );
};
```

### 3. Handling Login Result
The `login` function resolves with a result object (for popup flows) containing the OIDC state, the user, and the tokens. For redirect flows, the state is available via the `loginState` property in the context.

```tsx
const handleLogin = async () => {
  const result = await login({ 
    state: { returnUrl: '/dashboard' } 
  });
  
  if (result) {
    console.log("Flow state:", result.state);
    console.log("ID Token:", result.idToken);
  }
};
```

---

## ⚙️ Method 2: Manual Integration (Without Libraries)

If you cannot use a library, you must implement the **Authorization Code Flow with PKCE** manually.

### Step 1: Generate PKCE Verifier and Challenge
Before redirecting the user, cryptographically generate a high-entropy `code_verifier` and use SHA-256 to hash it into a `code_challenge`.

```javascript
// Pseudo-code for Browser APIs
const verifier = generateRandomString(43); // Ensure it's between 43-128 chars
const challenge = base64URLEncode(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
sessionStorage.setItem('pkce_verifier', verifier); // Store temporarily
```

### Step 2: Redirect to the Authorization Endpoint
Construct the URL and redirect the user's browser.

**Endpoint**: `GET https://auth.adolfrey.com/api/authorize`

**Parameters**:
- `client_id`: Your registered Client ID.
- `redirect_uri`: Whitelisted redirect URI for your app.
- `response_type`: Must be `code`.
- `state`: Random string to prevent CSRF attacks. Verify this on callback.
- `code_challenge`: The hashed string generated in Step 1.
- `code_challenge_method`: Must be `S256`.
- `scope`: E.g., `openid profile`. For cross-app access, use `api://{target-client-id}/{scope}`.

*Example URL with Cross-App Scope*:
`https://auth.adolfrey.com/api/authorize?client_id=my-app&redirect_uri=https://myapp.com/callback&response_type=code&state=xyz123&code_challenge=AbCdEf1234&code_challenge_method=S256&scope=openid%20profile%20api://inventory-service/read:stock`

### Step 3: Handle the Callback
The user will be redirected back to your `redirect_uri` with the parameters:
`?code=AUTH_CODE_HERE&state=xyz123`

Verify that the `state` matches the one you sent in Step 2. If it does, extract the `code`.

### Step 4: Exchange the Code for Tokens
Make a `POST` request to the Token endpoint, passing the `code` and the original `code_verifier`.

**Endpoint**: `POST https://auth.adolfrey.com/api/token`
**Content-Type**: `application/x-www-form-urlencoded` or `application/json`

**Payload**:
- `grant_type`: `authorization_code`
- `client_id`: Your Client ID.
- `redirect_uri`: Must match the redirect URI from Step 2.
- `code`: The code extracted from the URL.
- `code_verifier`: The original random string you stored in Step 1.
- `client_secret`: (Only required if your application is a backend/confidential client).

**Response**:
```json
{
  "access_token": "eyJhb...",
  "refresh_token": "dj9a...",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "openid profile api://inventory-service/read:stock"
}
```

### Step 5: Validate and Use the Token
The `access_token` is a Signed JWT. Use it in the `Authorization: Bearer <token>` header of subsequent API requests. The Backend will validate the signature against the public key found at `/.well-known/jwks.json`.

---

## 🌐 Cross-App Scopes & Trust

Atlas Rig supports **Cross-App Trust**, allowing one application (App A) to request access to resources/scopes owned by another application (App B).

### Qualified Scope Format
Cross-app scopes must use the following URI format:
`api://{target-client-id}/{scope-name}`

*Example:* `api://inventory-service/read:stock`

### Requirements for Access
For a cross-app scope to be granted in an access token, the following conditions must be met:

1.  **Trust Relationship:** An administrator must create a "Cross-App Trust" record in the Admin UI authorizing `App A` (Requesting Client) to request a specific scope from `App B` (Target Client).
2.  **Authorization Rule:** 
    *   For **User Sessions**: The user must have been manually assigned the scope for `App B`.
    *   For **App Principal Sessions**: The scope must be marked as **Client-Only (App Principal)**.
    *   **OR**, the scope must be marked as **Admin Approved (Auto-grant)** for `App B` (applies to user sessions).

### 🤖 App Principal Flow
Applications can request tokens directly using their own credentials to access trusted cross-app scopes.

**Token Request:**
`POST https://auth.adolfrey.com/api/token`

**Payload:**
- `grant_type`: `client_credentials`
- `client_id`: `app-a`
- `client_secret`: `secret-a`
- `scope`: `api://app-b/read:data`

### How to Request
Add the qualified scope to your authorization or token request alongside standard OIDC scopes.

#### Using OIDC Library
```typescript
const userManager = new UserManager({
    // ... other config
    scope: 'openid profile email api://inventory-service/read:stock'
});
```

#### Manual Redirect
`https://auth.adolfrey.com/api/authorize?client_id=my-app&...&scope=openid%20profile%20api://inventory-service/read:stock`

### JWT Representation
When granted, these scopes appear in the `scope` claim of the access token and are also mapped to the `role` claim to simplify integration with standard authorization middleware.

```json
{
  "sub": "user_123",
  "client_id": "my-app",
  "scope": "openid profile api://inventory-service/read:stock",
  "role": ["api://inventory-service/read:stock"]
}
```

---

## 🧪 Prototype UI Bypass

Atlas Rig provides a dedicated **Prototype UI Bypass** mode designed for UI-only prototypes. This mode allows you to simulate a complete authentication flow (with realistic-looking login screens) without needing to register a backend application, configure a database, or validate OIDC tokens.

### Implementing the Bypass

The easiest way to use the prototype bypass is via the **Atlas Rig Auth Client** library.

Simply add the `isPrototype: true` flag to your `AuthConfig`:

```tsx
import { AuthProvider } from 'ar-auth-client';

const config = {
  authority: 'https://auth.adolfrey.com',
  clientId: 'arbitrary-prototype-id', // No registration needed!
  redirectUri: window.location.origin + '/callback',
  scope: 'openid profile email',
  isPrototype: true // Automatically handles the prototype bypass
};
```

If you are not using the client library, you can manually append `&prototype=true` to the `/api/authorize` endpoint URL and handle the return `?code=prototype_bypass_code` yourself.

---

## 🔐 Backend Token Verification

After your frontend obtains an access token, your backend API must verify it before trusting the request. Atlas Rig provides official SDKs for **.NET**, **Python**, and **JavaScript/TypeScript**.

> **Important:** Token verification does NOT require `client_id` or `client_secret`. The SDK only needs the Authority URL to fetch the public signing keys (JWKS) and validate the RS256 signature.

### .NET (Ar.Auth.OpenId)

Install from GitHub Packages:
```bash
dotnet add package Ar.Auth.OpenId
dotnet add package Ar.Auth.OpenId.AspNetCore      # For ASP.NET Core
dotnet add package Ar.Auth.OpenId.AzureFunctions   # For Azure Functions
```

#### ASP.NET Core Web API
```csharp
using Ar.Auth.OpenId.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// One-liner: adds JWT Bearer auth pointing at Atlas Rig OIDC discovery
builder.Services.AddArAuth();
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/profile", (ClaimsPrincipal user) =>
{
    return Results.Ok(new { sub = user.FindFirst("sub")?.Value });
}).RequireAuthorization();

app.Run();
```

#### Azure Functions (Isolated Worker)
```csharp
using Ar.Auth.OpenId.AzureFunctions;

var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults(worker =>
    {
        worker.UseArAuth(
            configure: options => { options.Authority = "https://auth.adolfrey.com/api"; },
            configureMiddleware: mw => { mw.RequiredRoles = new[] { "admin" }; }
        );
    })
    .Build();
host.Run();
```

Then access the user in your function via `context.Items["ArAuthUser"]`.

#### Standalone Verification
```csharp
using Ar.Auth.OpenId;

var client = new ArAuthClient(); // defaults to https://auth.adolfrey.com/api
var principal = await client.VerifyTokenAsync("eyJhbGciOiJSUzI1Ni...");
Console.WriteLine($"User: {principal.FindFirst("sub")?.Value}");
```

---

### Python (ar-auth-client)

Install from PyPI:
```bash
pip install ar-auth-client
pip install ar-auth-client[fastapi]   # For FastAPI
pip install ar-auth-client[flask]     # For Flask
pip install ar-auth-client[azure]     # For Azure Functions
```

#### FastAPI
```python
from fastapi import FastAPI, Depends
from ar_auth.fastapi import ArAuthBearer

app = FastAPI()
admin_auth = ArAuthBearer(required_roles=["admin"])

@app.get("/admin/dashboard")
def get_dashboard(user_payload: dict = Depends(admin_auth)):
    return {"user_id": user_payload["sub"], "roles": user_payload["roles"]}
```

#### Flask
```python
from flask import Flask, jsonify, g
from ar_auth.flask import requires_auth

app = Flask(__name__)

@app.route("/api/profile")
@requires_auth(required_scopes=["profile"])
def get_profile():
    user = g.ar_auth_user
    return jsonify({"sub": user["sub"], "email": user.get("email")})
```

Note: `required_scopes` requires **all** listed scopes; `any_scopes` requires **at least one**.

#### Standalone Verification
```python
from ar_auth import ArAuthClient

client = ArAuthClient()  # defaults to https://auth.adolfrey.com/api
claims = client.verify_token("eyJhbGciOiJSUzI1Ni...")
print("User:", claims["sub"])
```

---

### JavaScript / TypeScript (ar-auth-client)

The frontend `ar-auth-client` library handles the full authentication flow. See [Method 3](#-method-3-using-atlas-rig-auth-client-highly-recommended) above for the frontend setup.

For backend (Node.js) token verification, use standard OIDC/JWT libraries such as `jose`:

```typescript
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(
  new URL('https://auth.adolfrey.com/.well-known/jwks.json')
);

async function verifyToken(token: string) {
  const { payload } = await jwtVerify(token, JWKS, {
    issuer: 'https://auth.adolfrey.com/api',
  });
  return payload;
}
```

---

## 📋 End-to-End Integration Summary

| Step | Frontend | Backend |
|---|---|---|
| **1. Login** | Use `ar-auth-client` (React) or `oidc-client-ts` to initiate the Authorization Code + PKCE flow | — |
| **2. Get Token** | Library exchanges the auth code for an `access_token` automatically | — |
| **3. API Call** | Send `Authorization: Bearer <access_token>` header with each request | — |
| **4. Verify Token** | — | Use `Ar.Auth.OpenId` (.NET), `ar-auth-client` (Python), or `jose` (Node.js) to validate the token's signature, issuer, and expiration |
| **5. Authorize** | — | Check `roles` and `scope` claims in the verified token to enforce access control |
