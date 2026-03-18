export const OAUTH_CONFIG = {
  authServer: 'http://localhost:7112', // Updated to match backend port and http
  authUi: 'https://localhost:5173',     // ar-auth frontend
  clientId: 'test-client',
  redirectUri: 'https://localhost:5174/callback',
  scopes: 'openid profile email',
};
