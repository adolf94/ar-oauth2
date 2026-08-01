import { UserManager, WebStorageStateStore, type UserManagerSettings, User as OidcUser } from 'oidc-client-ts';

export interface AuthConfig {
  authority?: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  popupRedirectUri?: string;
  automaticSilentRenew?: boolean;
  theme?: 'light' | 'dark';
  isPrototype?: boolean;
}

let _userManager: UserManager | null = null;
let _isPrototype = false;

export const initUserManager = (config: AuthConfig): UserManager => {
  if (_userManager) return _userManager;

  _isPrototype = config.isPrototype ?? false;

  const settings: UserManagerSettings = {
    authority: config.authority || 'https://auth.adolfrey.com/',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    popup_redirect_uri: config.popupRedirectUri || config.redirectUri,
    response_type: 'code',
    scope: config.scope,
    userStore: new WebStorageStateStore({ store: window.localStorage }),
    monitorSession: false,
    automaticSilentRenew: config.isPrototype ? false : (config.automaticSilentRenew ?? true),
    extraQueryParams: {
      ...(config.theme ? { theme: config.theme } : {}),
      ...(config.isPrototype ? { prototype: 'true' } : {}),
    },
  };

  _userManager = new UserManager(settings);
  return _userManager;
};

export const getUserManager = (): UserManager => {
  if (!_userManager) {
    throw new Error('UserManager not initialized. Call initUserManager() first.');
  }
  return _userManager;
};

let _activeRefreshPromises: Record<string, Promise<OidcUser | null> | undefined> = {};
let _refreshLock = Promise.resolve();

export const refreshAccessToken = async (scope?: string): Promise<OidcUser | null> => {
  // Never call the /token endpoint in prototype mode
  if (_isPrototype) {
    return null;
  }

  const scopeKey = scope || 'default';

  // If a refresh is already in progress for this EXACT scope, wait for it
  if (_activeRefreshPromises[scopeKey]) {
    return _activeRefreshPromises[scopeKey];
  }

  const executeRefresh = async (): Promise<OidcUser | null> => {
    const userManager = getUserManager();
    const user = await userManager.getUser();

    if (!user || !user.refresh_token) {
      return null;
    }

    try {
      const metadata = await userManager.metadataService.getMetadata();
      const tokenEndpoint = metadata.token_endpoint;

      if (!tokenEndpoint) {
        throw new Error('Token endpoint not found in metadata');
      }

      const params = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: user.refresh_token,
        client_id: userManager.settings.client_id,
        ...(scope ? { scope } : {}),
      });

      const response = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params,
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(`Refresh token request failed: ${errorData.error_description || errorData.error || response.statusText}`);
      }

      const tokenResponse = await response.json();

      // Create a new User object with updated tokens but keep existing profile data if not returned
      const newUser = new OidcUser({
        id_token: tokenResponse.id_token || user.id_token,
        access_token: tokenResponse.access_token,
        refresh_token: tokenResponse.refresh_token || user.refresh_token,
        token_type: tokenResponse.token_type || user.token_type,
        scope: tokenResponse.scope || user.scope,
        profile: user.profile,
        expires_at: Math.floor(Date.now() / 1000) + (tokenResponse.expires_in || 3600),
        session_state: tokenResponse.session_state || user.session_state,
      });

      await userManager.storeUser(newUser);
      return newUser;
    } catch (error) {
      console.error('Manual refresh failed:', error);
      return null;
    }
  };

  const promise = (async () => {
    // Wait for any previous refresh to finish (success or fail) to prevent concurrent uses of the same refresh_token
    await _refreshLock.catch(() => {});
    
    try {
      return await executeRefresh();
    } finally {
      delete _activeRefreshPromises[scopeKey];
    }
  })();

  _activeRefreshPromises[scopeKey] = promise;
  _refreshLock = promise.then(() => {}).catch(() => {});

  return promise;
};
