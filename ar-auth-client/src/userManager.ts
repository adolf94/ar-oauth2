import { UserManager, WebStorageStateStore, type UserManagerSettings, User as OidcUser } from 'oidc-client-ts';

export interface AuthConfig {
  authority?: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  popupRedirectUri?: string;
  automaticSilentRenew?: boolean;
  theme?: 'light' | 'dark';
}

let _userManager: UserManager | null = null;

export const initUserManager = (config: AuthConfig): UserManager => {
  if (_userManager) return _userManager;

  const settings: UserManagerSettings = {
    authority: config.authority || 'https://auth.adolfrey.com/',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    popup_redirect_uri: config.popupRedirectUri || config.redirectUri,
    response_type: 'code',
    scope: config.scope,
    userStore: new WebStorageStateStore({ store: window.localStorage }),
    monitorSession: false,
    automaticSilentRenew: config.automaticSilentRenew ?? true,
    extraQueryParams: {
      ...(config.theme ? { theme: config.theme } : {}),
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

export const refreshAccessToken = async (): Promise<OidcUser | null> => {
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
    // If refresh fails, we might want to clear the user to force a fresh login
    // but we'll leave that to the caller or until we're sure it's unrecoverable.
    return null;
  }
};
