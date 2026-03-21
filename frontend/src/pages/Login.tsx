import { Box, Button, Card, CardContent, Typography, Container, Avatar, IconButton, Divider, Paper } from '@mui/material';
import { Google as GoogleIcon, Fingerprint as FingerprintIcon, Telegram as TelegramIcon, DeleteOutline as DeleteIcon, History as HistoryIcon } from '@mui/icons-material';
import { useSearch } from '@tanstack/react-router';
import * as Passwordless from '@passwordlessdev/passwordless-client';
import api from '../api';
import ThemeSwitcher from '../components/ThemeSwitcher';
import { getRecentAccounts, removeRecentAccount, saveRecentAccount } from '../storage';
import type { RecentAccount } from '../storage';
import { useState, useEffect } from 'react';

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
  const [recentAccounts, setRecentAccounts] = useState<RecentAccount[]>([]);

  // No duplicate useEffect here anymore!

  const handleGoogleLogin = (hint?: string) => {
    const params = new URLSearchParams();
    if (searchParams.client_id) params.append('client_id', searchParams.client_id);
    if (searchParams.redirect_uri) params.append('redirect_uri', searchParams.redirect_uri);
    if (searchParams.state) params.append('state', searchParams.state);
    if (searchParams.code_challenge) params.append('code_challenge', searchParams.code_challenge);
    if (searchParams.code_challenge_method) params.append('code_challenge_method', searchParams.code_challenge_method);
    if (searchParams.scope) params.append('scope', searchParams.scope);
    if (hint) params.append('login_hint', hint);
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
        // Save to recently used
        if (data.user) {
          saveRecentAccount({
            id: data.user.id,
            email: data.user.email,
            provider: 'passkey'
          });
        }

        const redirectUrl = new URL(searchParams.redirect_uri, window.location.origin);
        redirectUrl.searchParams.set('code', data.code);
        if (searchParams.state) {
          redirectUrl.searchParams.set('state', searchParams.state);
        }
        window.location.href = redirectUrl.toString();
      } else {
        alert('Missing redirect URI or code from backend.');
      }
    } catch (err) {
      console.error("Passkey error:", err);
      alert('An error occurred during passkey login.');
    }
  };

  useEffect(() => {
    const fetchRecent = async () => {
      try {
        const res = await api.get('/accounts/recent');
        setRecentAccounts(res.data);
      } catch (err) {
        console.error('Failed to fetch recent accounts', err);
        // Fallback to localStorage for robustness
        setRecentAccounts(getRecentAccounts());
      }
    };
    fetchRecent();
  }, []);

  // ... (existing handlers)

  const handleRecentClick = (account: RecentAccount) => {
    if (account.provider === 'google') {
      handleGoogleLogin(account.email);
    } else {
      handlePasskeyLogin();
    }
  };

  const handleDeleteRecent = async (e: React.MouseEvent, account: RecentAccount) => {
    e.stopPropagation();
    try {
      await api.delete(`/accounts/recent/${account.id}`);
      removeRecentAccount(account.email); // Keep local storage in sync as fallback
      setRecentAccounts(prev => prev.filter(a => a.id !== account.id));
    } catch (err) {
      console.error('Delete failed', err);
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
            Atlas Rig
          </Typography>
        </Box>

        <Card sx={{ 
          boxShadow: (theme) => theme.palette.mode === 'dark' ? '0 8px 32px rgba(0,0,0,0.8)' : '0 8px 32px rgba(0,0,0,0.1)',
          borderRadius: 3,
          overflow: 'visible'
        }}>
          <CardContent sx={{ p: 4 }}>
            {recentAccounts.length > 0 && (
              <Box sx={{ mb: 4 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2, opacity: 0.7 }}>
                  <HistoryIcon fontSize="small" />
                  <Typography variant="caption" fontWeight={700} sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                    Recently Used
                  </Typography>
                </Box>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
                  {recentAccounts.map((account) => (
                    <Paper
                      key={account.email}
                      elevation={0}
                      onClick={() => handleRecentClick(account)}
                      sx={{
                        p: 1.5,
                        display: 'flex',
                        alignItems: 'center',
                        gap: 2,
                        cursor: 'pointer',
                        border: '1px solid',
                        borderColor: 'divider',
                        borderRadius: 2,
                        transition: 'all 0.2s',
                        '&:hover': {
                          borderColor: 'primary.main',
                          bgcolor: 'action.hover',
                          transform: 'translateY(-2px)'
                        }
                      }}
                    >
                      <Avatar sx={{ 
                        bgcolor: account.provider === 'google' ? '#ea4335' : 'secondary.main',
                        width: 32,
                        height: 32,
                        fontSize: '0.8rem'
                      }}>
                        {account.email[0].toUpperCase()}
                      </Avatar>
                      <Box sx={{ flex: 1, overflow: 'hidden' }}>
                        <Typography variant="body2" fontWeight={700} noWrap>
                          {account.email}
                        </Typography>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                           <Typography variant="caption" color="text.secondary">
                            via {account.provider}
                          </Typography>
                        </Box>
                      </Box>
                      <IconButton size="small" onClick={(e) => handleDeleteRecent(e, account)}>
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </Paper>
                  ))}
                </Box>
                <Box sx={{ my: 4, display: 'flex', alignItems: 'center', gap: 2 }}>
                  <Divider sx={{ flex: 1 }} />
                  <Typography variant="caption" color="text.disabled" sx={{ fontWeight: 700 }}>OR USE OTHER</Typography>
                  <Divider sx={{ flex: 1 }} />
                </Box>
              </Box>
            )}

            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <Button
                variant="outlined"
                fullWidth
                onClick={() => handleGoogleLogin()}
                startIcon={<GoogleIcon />}
                sx={{ py: 1.2, borderRadius: 2, borderColor: 'divider', color: 'text.primary', '&:hover': { borderColor: 'primary.main' }, fontWeight: 700 }}
              >
                Continue with Google
              </Button>

              <Button
                variant="outlined"
                fullWidth
                onClick={handleTelegramLogin}
                startIcon={<TelegramIcon />}
                sx={{ py: 1.2, borderRadius: 2, borderColor: 'divider', color: 'text.primary', '&:hover': { borderColor: 'primary.main' }, fontWeight: 700 }}
              >
                Continue with Telegram
              </Button>

              <Button
                variant="outlined"
                fullWidth
                color="secondary"
                onClick={handlePasskeyLogin}
                startIcon={<FingerprintIcon />}
                sx={{ py: 1.2, borderRadius: 2, fontWeight: 700 }}
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
