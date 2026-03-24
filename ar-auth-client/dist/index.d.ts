import { UserManager, User as User$1 } from 'oidc-client-ts';
import * as react_jsx_runtime from 'react/jsx-runtime';
import { ReactNode } from 'react';

interface AuthConfig {
    authority?: string;
    clientId: string;
    redirectUri: string;
    scope: string;
    popupRedirectUri?: string;
    automaticSilentRenew?: boolean;
    theme?: 'light' | 'dark';
}
declare const initUserManager: (config: AuthConfig) => UserManager;
declare const getUserManager: () => UserManager;
declare const refreshAccessToken: () => Promise<User$1 | null>;

interface User {
    email: string;
    name: string;
    picture: string;
    roles?: string[];
    scopes: string[];
}
interface AuthContextType {
    user: User | null;
    login: (options?: {
        useRedirect?: boolean;
    }) => Promise<void>;
    logout: () => void;
    isAuthenticated: boolean;
    isLoading: boolean;
    accessToken: string | null;
    hasScope: (scope: string) => boolean;
}
interface AuthProviderProps {
    children: ReactNode;
    config: AuthConfig;
}
declare const AuthProvider: ({ children, config }: AuthProviderProps) => react_jsx_runtime.JSX.Element;
declare const useAuth: () => AuthContextType;

export { type AuthConfig, AuthProvider, type AuthProviderProps, type User, getUserManager, initUserManager, refreshAccessToken, useAuth };
