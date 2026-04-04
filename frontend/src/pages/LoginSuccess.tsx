import { useEffect } from 'react';
import { useSearch } from '@tanstack/react-router';
import { Box, CircularProgress, Typography } from '@mui/material';
import { saveRecentAccount } from '../storage';

interface SuccessSearchParams {
  code?: string;
  state?: string;
  redirect_uri?: string;
  email?: string;
  id?: string;
  provider?: string;
}

export default function LoginSuccess() {
  const searchParams = useSearch({ strict: false }) as SuccessSearchParams;

  useEffect(() => {
    const { code, state, redirect_uri, email, id, provider } = searchParams;

    if (email && id) {
      saveRecentAccount({ 
        id, 
        email, 
        provider: (provider as 'google' | 'telegram' | 'passkey' | 'unknown') || 'google' 
      });
    }

    if (code && redirect_uri) {
      const redirectUrl = new URL(redirect_uri);
      redirectUrl.searchParams.set('code', code);
      if (state) {
        redirectUrl.searchParams.set('state', state);
      }
      window.location.href = redirectUrl.toString();
    } else {
      console.error('Missing code or redirect_uri', searchParams);
      window.location.href = '/';
    }
  }, [searchParams]);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100vh', gap: 2 }}>
      <CircularProgress />
      <Typography variant="h6">Finalizing login...</Typography>
    </Box>
  );
}
