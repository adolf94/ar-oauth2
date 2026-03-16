import { Box, Button, Card, CardContent, TextField, Typography, Container, Divider } from '@mui/material';
import { Google as GoogleIcon, Fingerprint as FingerprintIcon, Telegram as TelegramIcon } from '@mui/icons-material';
import { useSearch } from '@tanstack/react-router';
import { useState } from 'react';
import * as Passwordless from '@passwordlessdev/passwordless-client';
import api from '../api';
import ThemeSwitcher from '../components/ThemeSwitcher';

const PASSKEY_PUBLIC_KEY = 'arapps:public:45993b214ebd42049727f9a86f56b5eb';
const p = new Passwordless.Client({
  apiKey: PASSKEY_PUBLIC_KEY,
});

interface LoginSearchParams {
  client_id?: string;
  redirect_uri?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  scope?: string;
}

export default function Login() {
  const searchParams = useSearch({ strict: false }) as LoginSearchParams;

  const performLoginRequest = async (payload: any) => {
    try {
      const response = await api.post('/login', payload);
      const data = response.data;
      if (data.code && searchParams.redirect_uri) {
        window.location.href = `${searchParams.redirect_uri}?code=${data.code}&state=${searchParams.state || ''}`;
      } else {
        alert('Missing redirect URI or code from backend.');
      }
    } catch (err: any) {
      console.error("Login error:", err);
      alert('Login failed. Please check your credentials.');
    }
  };



  const handleGoogleLogin = () => {
    const params = new URLSearchParams();
    if (searchParams.client_id) params.append('client_id', searchParams.client_id);
    if (searchParams.redirect_uri) params.append('redirect_uri', searchParams.redirect_uri);
    if (searchParams.state) params.append('state', searchParams.state);
    if (searchParams.code_challenge) params.append('code_challenge', searchParams.code_challenge);
    if (searchParams.code_challenge_method) params.append('code_challenge_method', searchParams.code_challenge_method);
    if (searchParams.scope) params.append('scope', searchParams.scope);
    window.location.href = `/api/login/google?${params.toString()}`;
  };

  const handleTelegramLogin = () => {
    const params = new URLSearchParams();
    if (searchParams.client_id) params.append('client_id', searchParams.client_id);
    if (searchParams.redirect_uri) params.append('redirect_uri', searchParams.redirect_uri);
    if (searchParams.state) params.append('state', searchParams.state);
    if (searchParams.code_challenge) params.append('code_challenge', searchParams.code_challenge);
    if (searchParams.code_challenge_method) params.append('code_challenge_method', searchParams.code_challenge_method);
    if (searchParams.scope) params.append('scope', searchParams.scope);
    window.location.href = `/api/login/telegram?${params.toString()}`;
  };

  const handlePasskeyLogin = async () => {
    try {
      const { token, error } = await p.signinWithDiscoverable();
      if (error) {
        if (error.title !== 'UserCanceled') {
          console.error("Passkey error:", error);
          alert(`Passkey error: ${error.detail || error.title}`);
        }
        return;
      }
      const response = await api.post('/passkey/login', {
        token,
        client_id: searchParams.client_id,
        redirect_uri: searchParams.redirect_uri,
        state: searchParams.state,
        code_challenge: searchParams.code_challenge,
        code_challenge_method: searchParams.code_challenge_method,
        scope: searchParams.scope
      });
      const data = response.data;
      if (data.code && searchParams.redirect_uri) {
        window.location.href = `${searchParams.redirect_uri}?code=${data.code}&state=${searchParams.state || ''}`;
      } else {
        alert('Missing redirect URI or code from backend.');
      }
    } catch (err) {
      console.error("Passkey error:", err);
      alert('An error occurred during passkey login.');
    }
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        background: (theme) => theme.palette.mode === 'dark'
          ? 'radial-gradient(circle at 2% 2%, #1e1e20 0%, #0f0f0f 100%)'
          : 'radial-gradient(circle at 2% 2%, #ffffff 0%, #f4f1de 100%)',
        p: 3
      }}
    >
      <Box sx={{ position: 'absolute', top: 24, right: 24 }}>
        <ThemeSwitcher />
      </Box>

      <Container maxWidth="xs">
        <Box sx={{ mb: 4, textAlign: 'center' }}>
          <Typography variant="h3" fontWeight={700} gutterBottom sx={{ letterSpacing: -2, textTransform: 'uppercase' }}>
            LOGIN WITH <Box component="span" sx={{ color: 'primary.main', fontSize: '1.2em' }}>A</Box>&nbsp;<Box component="span" sx={{ color: 'primary.main', fontSize: '1.2em' }}>R</Box>
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>
            Atlas Runtime
          </Typography>
        </Box>

        <Card sx={{ boxShadow: (theme) => theme.palette.mode === 'dark' ? '0 8px 32px rgba(0,0,0,0.8)' : '0 8px 32px rgba(0,0,0,0.1)' }}>
          <CardContent sx={{ p: 4 }}>

            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <Button
                variant="outlined"
                fullWidth
                onClick={handleGoogleLogin}
                startIcon={<GoogleIcon />}
                sx={{ py: 1, borderColor: 'divider', color: 'text.primary', '&:hover': { borderColor: 'primary.main' } }}
              >
                Continue with Google
              </Button>

              <Button
                variant="outlined"
                fullWidth
                onClick={handleTelegramLogin}
                startIcon={<TelegramIcon />}
                sx={{ py: 1, borderColor: 'divider', color: 'text.primary', '&:hover': { borderColor: 'primary.main' } }}
              >
                Continue with Telegram
              </Button>

              <Button
                variant="outlined"
                fullWidth
                color="secondary"
                onClick={handlePasskeyLogin}
                startIcon={<FingerprintIcon />}
                sx={{ py: 1, fontWeight: 700 }}
              >
                Sign in with Passkey
              </Button>
            </Box>
          </CardContent>
        </Card>

        <Typography variant="caption" sx={{ display: 'block', mt: 4, textAlign: 'center', color: 'text.disabled', fontFamily: "'JetBrains Mono', monospace" }}>
          PRAGMATIC ARCHITECT SYSTEM v1.0
        </Typography>
      </Container>
    </Box>
  );
}
