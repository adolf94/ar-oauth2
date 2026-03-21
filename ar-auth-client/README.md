# @atlas-realm/auth

A reusable OIDC client SDK for ArGo applications, built on top of `oidc-client-ts`.

## Features

- **Robust Session Restoration**: Automatically restores user sessions on app load.
- **Manual Token Refresh**: Skips hidden iframes and uses the `refresh_token` grant directly for better compatibility with modern browsers.
- **React Context Integration**: Provides an `AuthProvider` and `useAuth` hook for easy integration.
- **Social In-App Support**: Automatically handles redirect-based login for environments like Facebook Messenger or Instagram where popups are blocked.

## Installation

```bash
npm install @atlas-realm/auth
```

## Usage

### 1. Initialize the Provider

Wrap your application with the `AuthProvider` and provide your OIDC configuration.

```tsx
import { AuthProvider } from '@atlas-realm/auth';

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
import { useAuth } from '@atlas-realm/auth';

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
```

## Technical Details

### Manual Token Refresh

This library uses a custom `refreshAccessToken` strategy to bypass the standard OIDC `prompt=none` iframe logic. It manually performs a `grant_type: refresh_token` request to the token endpoint, which is more reliable in browsers that restrict third-party cookies.
