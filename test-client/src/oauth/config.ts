export const OAUTH_CONFIG = {
  authServer: 'http://localhost:7071', // ar-auth backend
  authUi: 'http://localhost:5173',     // ar-auth frontend
  clientId: 'test-client',
  redirectUri: 'http://localhost:5174/callback',
  scopes: 'openid profile email',
};
