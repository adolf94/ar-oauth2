# AR Auth - OAuth 2.0 Integration Guide

Welcome to the **AR Auth** integration guide. This document explains how third-party and internal applications can connect to the AR Auth system to authenticate users via the **Authorization Code Flow with PKCE**.

## 🚀 Overview

AR Auth acts as a central Identity Provider (IdP) following OAuth 2.0 and OpenID Connect (OIDC) standards. 

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
- `scope`: E.g., `openid profile`.

*Example URL*:
`https://auth.adolfrey.com/api/authorize?client_id=my-app&redirect_uri=https://myapp.com/callback&response_type=code&state=xyz123&code_challenge=AbCdEf1234&code_challenge_method=S256&scope=openid%20profile`

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
  "scope": "openid profile"
}
```

### Step 5: Validate and Use the Token
The `access_token` is a Signed JWT. Use it in the `Authorization: Bearer <token>` header of subsequent API requests. The Backend will validate the signature against the public key found at `/.well-known/jwks.json`.
