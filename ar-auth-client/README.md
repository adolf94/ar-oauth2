# @adolf94/ar-auth-client

A reusable OIDC client SDK for ArGo applications, built on top of `oidc-client-ts`.

## Features

- **Robust Session Restoration**: Automatically restores user sessions on app load.
- **Manual Token Refresh**: Skips hidden iframes and uses the `refresh_token` grant directly for better compatibility with modern browsers.
- **React Context Integration**: Provides an `AuthProvider` and `useAuth` hook for easy integration.
- **Social In-App Support**: Automatically handles redirect-based login for environments like Facebook Messenger or Instagram where popups are blocked.
- **Prototype UI Bypass**: Seamlessly supports `ar-auth`'s prototype bypass mode to fake authenticated sessions without backend validation.

## Installation

```bash
npm install @adolf94/ar-auth-client
```

## Features

### Prototype UI Bypass

If you are developing a UI-only prototype that does not have a backend to validate standard OIDC authorization codes, `ar-auth-client` natively supports `ar-auth`'s **UI Bypass** mode. 

To enable this, simply set `isPrototype: true` when initializing your `AuthProvider`:

```tsx
const authConfig = {
  authority: 'https://auth.example.com',
  clientId: 'my-client-id',
  redirectUri: window.location.origin + '/callback',
  scope: 'openid profile email',
  isPrototype: true, // Enables the Prototype UI Bypass
};
```

When a user clicks "Continue to App (UI Bypass)" on the `ar-auth` login screen:
1. **Popup Flow**: `ar-auth` broadcasts a `PROTOTYPE_LOGIN_SUCCESS` signal to the opener window. `ar-auth-client` intercepts this signal and immediately resolves the `login()` Promise with a dummy user.
2. **Redirect Flow**: `ar-auth` redirects back to your application with `?code=prototype_bypass_code`. `ar-auth-client` detects this code on load and automatically establishes a fake session.

In both flows, your application will instantly behave as if a user successfully logged in, providing a mocked user profile (`Prototype User`, `prototype@example.com`) and access token (`dummy_access_token`). No other configuration changes are required on your end!

## Usage

### 1. Initialize the Provider

Wrap your application with the `AuthProvider` and provide your OIDC configuration.

```tsx
import { AuthProvider } from '@adolf94/ar-auth-client';

const authConfig = {
  authority: 'https://auth.example.com',
  clientId: 'my-client-id',
  redirectUri: window.location.origin + '/callback',
  scope: 'openid profile email offline_access',
};

function App() {
  return (
    <AuthProvider config={authConfig}>
      <YourAppContent />
    </AuthProvider>
  );
}
```

### 2. Use the Auth Hook

```tsx
import { useAuth } from '@adolf94/ar-auth-client';

function YourComponent() {
  const { user, login, logout, isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return <button onClick={() => login()}>Login</button>;
  }

  return (
    <div>
      <p>Hello, {user?.name}!</p>
      <button onClick={logout}>Logout</button>
    </div>
  );
}

### 3. Handling Login Rejections

The `login` function returns a promise that rejects if the process is cancelled or fails. This is especially useful for detecting when a user closes the login popup.

```tsx
const { login } = useAuth();
const [isLoggingIn, setIsLoggingIn] = useState(false);

const handleLogin = async () => {
  setIsLoggingIn(true);
  try {
    await login();
  } catch (error: any) {
    if (error.message === 'Popup closed') {
      alert('Login was cancelled by the user.');
    } else {
      console.error('Authentication Error:', error);
    }
  } finally {
    setIsLoggingIn(false);
  }
};
```

### 4. Fetching Tokens for Specific Scopes (Downscoping)

If you need an access token with a specific subset of scopes (e.g., for a different microservice), use `getAccessToken`. This will automatically check if your current token is valid for that scope and perform a silent refresh if needed.

```tsx
const { getAccessToken } = useAuth();

const callApi = async () => {
    // Requests a token specifically with 'products:read' scope
    const token = await getAccessToken('products:read');
    
    if (token) {
        const response = await fetch('https://api.example.com/products', {
            headers: { Authorization: `Bearer ${token}` }
        });
        // ...
    }
};
```
```

## Technical Details




### Manual Token Refresh

This library uses a custom `refreshAccessToken` strategy to bypass the standard OIDC `prompt=none` iframe logic. It manually performs a `grant_type: refresh_token` request to the token endpoint, which is more reliable in browsers that restrict third-party cookies.
