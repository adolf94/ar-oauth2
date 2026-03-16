import { type ReactNode, useEffect, useState } from 'react';
import { useNavigate, useLocation } from '@tanstack/react-router';

interface AuthGuardProps {
  children: ReactNode;
  requiredRole?: string;
}

export default function AuthGuard({ children, requiredRole }: AuthGuardProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const [isAuthorized, setIsAuthorized] = useState(false);

  useEffect(() => {
    const token = sessionStorage.getItem('access_token');

    if (!token) {
      const initiateLogin = async () => {
        const { verifier, challenge } = await import('../pkce').then(m => m.generatePkce());
        sessionStorage.setItem('pkce_verifier', verifier);

        // Redirect to central auth system
        const params = new URLSearchParams({
          client_id: 'ar-auth-management',
          redirect_uri: window.location.origin + '/auth/callback',
          state: location.pathname,
          scope: 'openid profile manage admin',
          response_type: 'code',
          code_challenge: challenge,
          code_challenge_method: 'S256'
        });
        const authUri = window.webConfig?.authUri;
        window.location.href = `${authUri}/api/authorize?${params.toString()}`;
      };

      initiateLogin();
      return;
    }

    // Optional: Decode token to check for requiredRole
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      if (requiredRole && (!payload.role || !payload.role.includes(requiredRole))) {
        console.error('User does not have required role:', requiredRole);
        navigate({ to: '/' });
        return;
      }
      setIsAuthorized(true);
    } catch (e) {
      console.error('Failed to parse token', e);
      sessionStorage.removeItem('access_token');
      window.location.reload();
    }
  }, [location, navigate, requiredRole]);

  if (!isAuthorized) {
    return null; // Or a loading spinner
  }

  return <>{children}</>;
}
