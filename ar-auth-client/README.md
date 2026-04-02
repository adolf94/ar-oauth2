# @adolf94/ar-auth-client

A reusable OIDC client SDK for ArGo applications, built on top of `oidc-client-ts`.

## Features

- **Robust Session Restoration**: Automatically restores user sessions on app load.
- **Manual Token Refresh**: Skips hidden iframes and uses the `refresh_token` grant directly for better compatibility with modern browsers.
- **React Context Integration**: Provides an `AuthProvider` and `useAuth` hook for easy integration.
- **Social In-App Support**: Automatically handles redirect-based login for environments like Facebook Messenger or Instagram where popups are blocked.

## Installation

```bash
npm install @adolf94/ar-auth-client
```

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
