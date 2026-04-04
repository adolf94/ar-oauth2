import { useEffect, useState, useRef } from 'react';
import { useSearch } from '@tanstack/react-router';
import { Box, CircularProgress, Typography } from '@mui/material';

export default function AuthCallback() {
  const searchParams = useSearch({ strict: false }) as { code?: string, state?: string };
  const [error, setError] = useState<string | null>(null);
  const processed = useRef(false);

  useEffect(() => {
    if (processed.current) return;

    const code = searchParams.code;
    const state = searchParams.state;

    if (!code) {
      setError('No authorization code found in URL.');
      return;
    }

    processed.current = true;

    // Exchange code for token
    const fetchToken = async () => {
      try {
        const verifier = sessionStorage.getItem('pkce_verifier') || '';
        sessionStorage.removeItem('pkce_verifier'); // Clean up

        const authUri = window.webConfig?.authUri || 'https://auth.adolfrey.com';
        const response = await fetch(`${authUri}/api/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            grant_type: 'authorization_code',
            code,
            client_id: 'ar-auth-management',
            redirect_uri: window.location.origin + '/auth/callback',
            code_verifier: verifier
          }),
        });

        if (!response.ok) {
          const detail = await response.text();
          throw new Error(detail || 'Failed to exchange code for token.');
        }

        const data = await response.json();
        if (data.access_token) {
          sessionStorage.setItem('access_token', data.access_token);
          if (data.refresh_token) {
            sessionStorage.setItem('refresh_token', data.refresh_token);
          }
          // Redirect to the original state (path) or home
          const target = state || '/';
          window.location.href = target;
        } else {
          throw new Error('No access token returned from server.');
        }
      } catch (err: unknown) {
        console.error('AuthCallback error:', err);
        setError(err instanceof Error ? err.message : 'Unknown error');
      }
    };

    fetchToken();
  }, [searchParams]);

  if (error) {
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', mt: 10 }}>
        <Typography color="error" variant="h6">Authentication Error</Typography>
        <Typography variant="body1">{error}</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', mt: 10 }}>
      <CircularProgress />
      <Typography sx={{ mt: 2 }}>Finishing sign-in...</Typography>
    </Box>
  );
}
