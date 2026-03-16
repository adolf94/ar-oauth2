import { useEffect, useState } from 'react';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { Container, Typography, CircularProgress, Box, Alert } from '@mui/material';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { OAUTH_CONFIG } from '../oauth/config';

export default function Callback() {
  const search = useSearch({ from: '/callback' }) as { code?: string; state?: string; error?: string };
  const navigate = useNavigate();
  const { setTokens } = useAuth();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function exchangeCode() {
      if (search.error) {
        setError(`OAuth Error: ${search.error}`);
        return;
      }

      const code = search.code;
      const state = search.state;
      const savedState = sessionStorage.getItem('oauth_state');
      const verifier = sessionStorage.getItem('pkce_verifier');

      if (!code || !state || !verifier) {
        setError('Missing required OAuth parameters.');
        return;
      }

      if (state !== savedState) {
        setError('State mismatch — potential CSRF.');
        return;
      }

      try {
        const response = await axios.post(`${OAUTH_CONFIG.authServer}/api/token`, {
          grant_type: 'authorization_code',
          code: code,
          client_id: OAUTH_CONFIG.clientId,
          redirect_uri: OAUTH_CONFIG.redirectUri,
          code_verifier: verifier
        });

        const { access_token, id_token } = response.data;
        setTokens(access_token, id_token);
        navigate({ to: '/' });
      } catch (err: any) {
        console.error('Token exchange failed:', err);
        setError(err.response?.data?.error_description || err.message || 'Token exchange failed.');
      }
    }

    exchangeCode();
  }, [search, navigate, setTokens]);

  if (error) {
    return (
      <Container sx={{ mt: 8 }}>
        <Alert severity="error" variant="filled">
          <Typography variant="h6">Authentication Failed</Typography>
          {error}
        </Alert>
        <Box sx={{ mt: 2, textAlign: 'center' }}>
          <a href="/">Back to Home</a>
        </Box>
      </Container>
    );
  }

  return (
    <Container sx={{ mt: 8, textAlign: 'center' }}>
      <CircularProgress size={60} />
      <Typography variant="h6" sx={{ mt: 2 }}>
        Finishing login...
      </Typography>
    </Container>
  );
}
