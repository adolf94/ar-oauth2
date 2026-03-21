import { createContext, useContext, useState, useEffect, type ReactNode } from 'react';
import { type User as OidcUser } from 'oidc-client-ts';
import { getUserManager, initUserManager, refreshAccessToken, type AuthConfig } from './userManager';

export interface User {
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
  hasScope: (scope: string) => boolean;
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

  const audience = clientId === 'ar-go-web' ? 'ar-go-api' : '';
  const prefix = `api://${audience}/`;
  
  const scopes = allPermissions
    .filter(p => p.startsWith('api://'))
    .map(p => p.startsWith(prefix) ? p.substring(prefix.length) : p);

  const uniqueScopes = Array.from(new Set(scopes));
  const uniqueRoles = Array.from(new Set(allPermissions.filter(p => !p.includes('://') || p.startsWith('api://'))));

  return {
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
  const [isLoading, setIsLoading] = useState(true);

  // Ensure UserManager is initialized
  const userManager = initUserManager(config);

  useEffect(() => {
    const restore = async () => {
      try {
        const params = new URLSearchParams(window.location.search);
        const code = params.get('code');
        const state = params.get('state');

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
          setUser(mapOidcUser(oidcUser, config.clientId));
          setAccessToken(oidcUser.access_token);
        }
      } catch (e) {
        console.error('Failed to restore session:', e);
      } finally {
        setIsLoading(false);
      }
    };
    restore();

    const onUserLoaded = (oidcUser: OidcUser) => {
      setUser(mapOidcUser(oidcUser, config.clientId));
      setAccessToken(oidcUser.access_token);
    };

    const onSilentRenewError = (error: Error) => {
      console.error('Silent renew failed:', error);
      setUser(null);
      setAccessToken(null);
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
      setUser(mapOidcUser(oidcUser, config.clientId));
      setAccessToken(oidcUser.access_token);
    } catch (error) {
      console.error('Login failed:', error);
      throw error;
    }
  };

  const logout = () => {
    userManager.removeUser();
    setUser(null);
    setAccessToken(null);
  };

  const hasScope = (scope: string) => {
    return user?.scopes.some(s => s.toLowerCase() === scope.toLowerCase()) ?? false;
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, isAuthenticated: !!user, isLoading, accessToken, hasScope }}>
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
