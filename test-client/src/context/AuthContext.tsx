import React, { createContext, useContext, useState, useEffect } from 'react';

interface AuthState {
  accessToken: string | null;
  idToken: string | null;
  isAuthenticated: boolean;
}

interface AuthContextType extends AuthState {
  login: () => Promise<void>;
  logout: () => void;
  setTokens: (access: string, id: string | null) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

import { OAUTH_CONFIG } from '../oauth/config';
import { generateCodeVerifier, generateCodeChallenge } from '../oauth/pkce';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [state, setState] = useState<AuthState>({
    accessToken: sessionStorage.getItem('access_token'),
    idToken: sessionStorage.getItem('id_token'),
    isAuthenticated: !!sessionStorage.getItem('access_token'),
  });

  const login = async () => {
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    const stateVal = Math.random().toString(36).substring(7);

    sessionStorage.setItem('pkce_verifier', verifier);
    sessionStorage.setItem('oauth_state', stateVal);

    const params = new URLSearchParams({
      client_id: OAUTH_CONFIG.clientId,
      redirect_uri: OAUTH_CONFIG.redirectUri,
      response_type: 'code',
      scope: OAUTH_CONFIG.scopes,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: stateVal,
    });

    // Redirect to ar-auth UI login page
    window.location.href = `${OAUTH_CONFIG.authUi}/login?${params.toString()}`;
  };

  const logout = () => {
    sessionStorage.removeItem('access_token');
    sessionStorage.removeItem('id_token');
    sessionStorage.removeItem('pkce_verifier');
    sessionStorage.removeItem('oauth_state');
    setState({ accessToken: null, idToken: null, isAuthenticated: false });
  };

  const setTokens = (access: string, id: string | null) => {
    sessionStorage.setItem('access_token', access);
    if (id) sessionStorage.setItem('id_token', id);
    setState({ accessToken: access, idToken: id, isAuthenticated: true });
  };

  return (
    <AuthContext.Provider value={{ ...state, login, logout, setTokens }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within an AuthProvider');
  return context;
};
