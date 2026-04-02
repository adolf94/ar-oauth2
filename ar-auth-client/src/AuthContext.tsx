import { createContext, useContext, useState, useEffect, type ReactNode } from 'react';
import { type User as OidcUser } from 'oidc-client-ts';
import { getUserManager, initUserManager, refreshAccessToken, type AuthConfig } from './userManager';

export interface User {
  userId: string;
  email: string;
  name: string;
  picture: string;
  roles?: string[];
  scopes: string[];
}

interface AuthContextType {
  user: User | null;
  login: (options?: { useRedirect?: boolean }) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
  isLoading: boolean;
  accessToken: string | null;
  accessTokens: Record<string, { token: string; expiresAt: number }>;
  hasScope: (scope: string) => boolean;
  getAccessToken: (scope?: string) => Promise<string | null>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const mapOidcUser = (oidcUser: OidcUser, clientId: string): User => {
  const profile = oidcUser.profile;
  const rawItems = [
    (profile as any)['roles'],
    (profile as any)['role'],
    (profile as any)['scp'],
    (profile as any)['scope'],
    oidcUser.scope
  ];

  const allPermissions: string[] = [];
  rawItems.forEach(item => {
    if (!item) return;
    if (Array.isArray(item)) {
      allPermissions.push(...item.map(String));
    } else if (typeof item === 'string') {
      allPermissions.push(...item.split(' ').filter(Boolean));
    }
  });

  const prefix = `api://${clientId}/`;

  const scopes = allPermissions
    .filter(p => p.startsWith('api://'))
    .map(p => p.startsWith(prefix) ? p.substring(prefix.length) : p);

  const uniqueScopes = Array.from(new Set(scopes));
  const uniqueRoles = Array.from(new Set(allPermissions.filter(p => !p.includes('://') || p.startsWith('api://'))));

  return {
    userId: (profile as any)['userId'] ?? profile.sub ?? '',
    email: profile.email ?? '',
    name: profile.name ?? '',
    picture: (profile as any)['picture'] ?? '',
    roles: uniqueRoles,
    scopes: uniqueScopes
  };
};

export interface AuthProviderProps {
  children: ReactNode;
  config: AuthConfig;
}

export const AuthProvider = ({ children, config }: AuthProviderProps) => {
  const [user, setUser] = useState<User | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [accessTokens, setAccessTokens] = useState<Record<string, { token: string; expiresAt: number }>>({});
  const [isLoading, setIsLoading] = useState(true);

  // Ensure UserManager is initialized
  const userManager = initUserManager(config);

  useEffect(() => {
    const restore = async () => {
      try {
        const params = new URLSearchParams(window.location.search);
        const code = params.get('code');
        const state = params.get('state');

        if (window.opener && (code || state)) {
          try {
            await userManager.signinPopupCallback();
            return;
          } catch (err) {
            console.error('Popup callback failed:', err);
          }
        }

        if (!window.opener && code && state) {
          try {
            await userManager.signinRedirectCallback();
            window.history.replaceState({}, document.title, window.location.pathname);
          } catch (err) {
            console.error('Redirect callback failed:', err);
          }
        }

        let oidcUser = await userManager.getUser();

        if (!oidcUser || oidcUser.expired) {
          try {
            oidcUser = await refreshAccessToken();
          } catch (err) {
            console.warn('Manual refresh on load failed:', err);
          }
        }

        if (oidcUser && !oidcUser.expired) {
          updateUserState(oidcUser);
        }
      } catch (e) {
        console.error('Failed to restore session:', e);
      } finally {
        setIsLoading(false);
      }
    };
    restore();

    const onUserLoaded = (oidcUser: OidcUser) => {
      updateUserState(oidcUser);
    };

    const onSilentRenewError = (error: Error) => {
      console.error('Silent renew failed:', error);
      setUser(null);
      setAccessToken(null);
      setAccessTokens({});
    };

    userManager.events.addUserLoaded(onUserLoaded);
    userManager.events.addSilentRenewError(onSilentRenewError);

    return () => {
      userManager.events.removeUserLoaded(onUserLoaded);
      userManager.events.removeSilentRenewError(onSilentRenewError);
    };
  }, [userManager, config.clientId]);

  const login = async (options?: { useRedirect?: boolean }) => {
    try {
      const ua = navigator.userAgent || navigator.vendor || (window as any).opera;
      const isSocialInApp = /FBAN|FBAV|Instagram|Messenger|WhatsApp/i.test(ua);
      const isIOS = /iPad|iPhone|iPod/.test(ua) && !(window as any).MSStream;

      if (options?.useRedirect || isSocialInApp || isIOS) {
        await userManager.signinRedirect();
        return;
      }

      const oidcUser = await userManager.signinPopup();
      updateUserState(oidcUser);
    } catch (error: any) {
      if (error?.message === 'Popup closed') {
        console.warn('Authentication popup was closed by the user.');
      } else {
        console.error('Login failed:', error);
      }
      // Re-throw so the 3rd party app can catch it
      throw error;
    }
  };

  const logout = () => {
    userManager.removeUser();
    setUser(null);
    setAccessToken(null);
    setAccessTokens({});

    // Clear session storage cache
    const prefix = `ar_auth_token_${config.clientId}_`;
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key && key.startsWith(prefix)) {
        sessionStorage.removeItem(key);
        i--; // Adjust index after removal
      }
    }
  };

  const updateUserState = (oidcUser: OidcUser) => {
    const mappedUser = mapOidcUser(oidcUser, config.clientId);
    
    setUser(prev => {
      if (!prev || prev.userId !== mappedUser.userId) return mappedUser;
      
      // Merge scopes and roles
      const mergedScopes = Array.from(new Set([...prev.scopes, ...mappedUser.scopes]));
      const mergedRoles = Array.from(new Set([...(prev.roles || []), ...(mappedUser.roles || [])]));
      
      return {
        ...mappedUser,
        scopes: mergedScopes,
        roles: mergedRoles
      };
    });

    setAccessToken(oidcUser.access_token);
    
    setAccessTokens(prev => ({
      ...prev,
      [oidcUser.scope || config.scope]: {
        token: oidcUser.access_token,
        expiresAt: oidcUser.expires_at || 0
      }
    }));

    // Cache in session storage for scope-specific reuse
    const storageKey = `ar_auth_token_${config.clientId}_${oidcUser.scope || config.scope}`;
    sessionStorage.setItem(storageKey, JSON.stringify({
      token: oidcUser.access_token,
      expiresAt: oidcUser.expires_at
    }));
  };
  const getAccessToken = async (scope?: string): Promise<string | null> => {
    const currentScope = scope || config.scope;
    
    // 1. Check React state (Fastest)
    const stateCached = accessTokens[currentScope];
    if (stateCached && stateCached.expiresAt > (Date.now() / 1000) + 30) {
      return stateCached.token;
    }

    const storageKey = `ar_auth_token_${config.clientId}_${currentScope}`;

    // 2. Check Session Storage Cache (Persistent across reloads)
    const stored = sessionStorage.getItem(storageKey);
    if (stored) {
      try {
        const { token, expiresAt } = JSON.parse(stored);
        if (expiresAt > (Date.now() / 1000) + 30) {
          // Sync back to React state for next call
          setAccessTokens(prev => ({ ...prev, [currentScope]: { token, expiresAt } }));
          return token;
        }
      } catch (e) {
        sessionStorage.removeItem(storageKey);
      }
    }

    let oidcUser = await userManager.getUser();

    if (scope && oidcUser && !oidcUser.expired) {
      const userScopes = oidcUser.scope?.split(' ') || [];
      if (!userScopes.includes(scope)) {
        oidcUser = null; // Forces refresh with new scope
      }
    }

    if (!oidcUser || oidcUser.expired) {
      try {
        oidcUser = await refreshAccessToken(scope);
        if (oidcUser) {
          updateUserState(oidcUser);
        }
      } catch (err) {
        console.error('Failed to get access token:', err);
        return null;
      }
    }

    return oidcUser?.access_token ?? null;
  };

  const hasScope = (scope: string) => {
    const fullScope = `api://${config.clientId}/${scope}`.toLowerCase();
    return user?.scopes.some(s => {
      const sLower = s.toLowerCase();
      return sLower === scope.toLowerCase() ||
        sLower === fullScope || fullScope === "*";
    }) ?? false;
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, isAuthenticated: !!user, isLoading, accessToken, accessTokens, hasScope, getAccessToken }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
