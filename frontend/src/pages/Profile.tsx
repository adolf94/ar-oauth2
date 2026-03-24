import { Box, Button, Card, CardContent, Chip, CircularProgress, Divider, List, ListItem, ListItemText, Typography, IconButton, Container, TextField } from '@mui/material';
import { Delete as DeleteIcon, Fingerprint as FingerprintIcon, AdminPanelSettings as AdminIcon } from '@mui/icons-material';
import { useEffect, useState } from 'react';
import * as Passwordless from '@passwordlessdev/passwordless-client';
import api from '../api';
import ThemeSwitcher from '../components/ThemeSwitcher';
import { useNavigate } from '@tanstack/react-router';
import { saveRecentAccount } from '../storage';

const PASSKEY_PUBLIC_KEY = 'arapps:public:45993b214ebd42049727f9a86f56b5eb';
const p = new Passwordless.Client({
  apiKey: PASSKEY_PUBLIC_KEY,
});

interface UserProfile {
  id: string;
  email: string;
  roles: string[];
  externalIdentities: Record<string, string>;
}

interface Passkey {
  descriptor: { id: string };
  nickname: string;
  createdAt: string;
  lastUsedAt: string;
  credentialId: string;
}

export default function Profile() {
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [loading, setLoading] = useState(true);


  const navigate = useNavigate();

  const fetchProfile = async () => {
    try {
      const res = await api.get('/profile');
      setProfile(res.data);
      // Save to recently used accounts
      saveRecentAccount({
        id: res.data.id,
        email: res.data.email,
        provider: 'unknown' // We don't know the exact provider from profile alone, but email is what matters
      });
    } catch (err) {
      console.error('Failed to fetch profile', err);
    }
  };

  const fetchPasskeys = async () => {
    try {
      const res = await api.get('/passkey/list');
      setPasskeys(res.data);
    } catch (err) {
      console.error('Failed to fetch passkeys', err);
    }
  };

  useEffect(() => {
    Promise.all([fetchProfile(), fetchPasskeys()]).finally(() => setLoading(false));
  }, []);

  const handleRegisterPasskey = async (nickname: string) => {
    try {
      const res = await api.post('/passkey/register/start', {
        email: profile?.email,
        nickname: nickname
      });
      const registerToken = res.data.token;

      const { error } = await p.register(registerToken);

      if (error) {
        alert(`Registration failed: ${error.detail || error.title}`);
      } else {
        alert('Passkey registered successfully!');
        fetchPasskeys();
      }
    } catch (err) {
      console.error('Registration error', err);
      alert('An error occurred during registration.');
    }
  };

  const handleDeletePasskey = async (credentialId: string) => {
    if (!confirm('Are you sure you want to delete this passkey?')) return;
    try {
      await api.delete(`/passkey/${credentialId}`);
      setPasskeys(prev => prev.filter(pk => pk.credentialId !== credentialId));
    } catch (err) {
      console.error('Delete error', err);
    }
  };


  const handleLinkAccount = async (provider: 'google' | 'telegram') => {
    try {
      // 1. Get a secure link token from the backend
      const res = await api.post('/profile/link-token');
      const { link_token } = res.data;

      // 2. Redirect to the login endpoint with the link_token
      // We pass the same client_id and redirect_uri as a normal login but with link_token
      const params = new URLSearchParams();
      params.append('client_id', 'ar-auth-web'); // Or whatever the frontend client ID is
      params.append('redirect_uri', `${window.location.origin}/login/success`);
      params.append('link_token', link_token);
      params.append('state', 'linking'); // For UI state
      
      window.location.href = `/api/login/${provider}?${params.toString()}`;
    } catch (err) {
      console.error('Linking error', err);
      alert('Failed to initiate linking process.');
    }
  };

  if (loading) return <CircularProgress sx={{ display: 'block', m: 'auto', mt: 10, color: 'primary.main' }} />;

  const isAdmin = profile?.roles.includes('admin');

  return (
    <Container maxWidth="md" sx={{ py: 8 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 6 }}>
        <Box>
          <Typography variant="h3" fontWeight={700} sx={{ letterSpacing: -1 }}>
            Account <Box component="span" sx={{ color: 'primary.main' }}>Settings</Box>
          </Typography>
          <Typography color="text.secondary" sx={{ fontFamily: "'JetBrains Mono', monospace", mt: 1 }}>
            Manage your identity and security tokens.
          </Typography>
        </Box>
        <ThemeSwitcher />
      </Box>

      {isAdmin && (
        <Card sx={{ mb: 4, bgcolor: 'rgba(161, 0, 255, 0.05)', borderColor: 'primary.main', borderStyle: 'dashed' }}>
          <CardContent sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <AdminIcon color="primary" fontSize="large" />
              <Box>
                <Typography variant="h6" fontWeight={700}>Administrative Console</Typography>
                <Typography variant="body2" color="text.secondary">You have elevated privileges. Manage apps and users.</Typography>
              </Box>
            </Box>
            <Button
              variant="contained"
              onClick={() => navigate({ to: '/admin' })}
              sx={{ fontFamily: "'JetBrains Mono', monospace" }}
            >
              Go to Admin Dashboard
            </Button>
          </CardContent>
        </Card>
      )}

      <Card sx={{ mb: 4 }}>
        <CardContent sx={{ p: 4 }}>
          <Typography variant="h6" gutterBottom fontWeight={700} sx={{ fontFamily: "'JetBrains Mono', monospace" }}>
            Profile Details
          </Typography>
          <Divider sx={{ mb: 3 }} />
          <Box sx={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: 2 }}>
            <Typography color="text.secondary" sx={{ fontFamily: "'JetBrains Mono', monospace" }}>Email</Typography>
            <Typography fontWeight={600}>{profile?.email}</Typography>

            <Typography color="text.secondary" sx={{ fontFamily: "'JetBrains Mono', monospace" }}>User ID</Typography>
            <Typography sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.85rem', color: 'text.secondary' }}>{profile?.id}</Typography>

            <Typography color="text.secondary" sx={{ fontFamily: "'JetBrains Mono', monospace" }}>Roles</Typography>
            <Box sx={{ display: 'flex', gap: 1 }}>
              {profile?.roles.map(role => (
                <Chip key={role} label={role} size="small" color="primary" variant="outlined" sx={{ borderRadius: 1, fontWeight: 700 }} />
              ))}
            </Box>
          </Box>
        </CardContent>
      </Card>

      <Card sx={{ mb: 4 }}>
        <CardContent sx={{ p: 4 }}>
          <Typography variant="h6" fontWeight={700} sx={{ fontFamily: "'JetBrains Mono', monospace", mb: 2 }}>
            Connected Identities
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Link external providers to sign in with your preferred account.
          </Typography>
          <Divider sx={{ mb: 3 }} />
          
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {/* Google */}
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', p: 2, bgcolor: 'background.default', borderRadius: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <Typography fontWeight={600}>Google</Typography>
                {profile?.externalIdentities['google'] ? (
                  <Chip label="Connected" size="small" color="success" variant="outlined" />
                ) : (
                  <Chip label="Not Linked" size="small" variant="outlined" />
                )}
              </Box>
              {!profile?.externalIdentities['google'] && (
                <Button variant="outlined" size="small" onClick={() => handleLinkAccount('google')}>Link Account</Button>
              )}
            </Box>

            {/* Telegram */}
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', p: 2, bgcolor: 'background.default', borderRadius: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <Typography fontWeight={600}>Telegram</Typography>
                {profile?.externalIdentities['telegram'] ? (
                  <Chip label="Connected" size="small" color="success" variant="outlined" />
                ) : (
                  <Chip label="Not Linked" size="small" variant="outlined" />
                )}
              </Box>
              {!profile?.externalIdentities['telegram'] && (
                <Button variant="outlined" size="small" onClick={() => handleLinkAccount('telegram')}>Link Account</Button>
              )}
            </Box>
          </Box>
        </CardContent>
      </Card>


      <Card>
        <CardContent sx={{ p: 4 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Box sx={{ flex: 1, mr: 2 }}>
              <Typography variant="h6" fontWeight={700} sx={{ fontFamily: "'JetBrains Mono', monospace" }}>
                Passkeys (WebAuthn)
              </Typography>
              <Typography variant="body2" color="text.secondary">Secure biometric authentication.</Typography>
            </Box>
            <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
              <TextField
                size="small"
                placeholder="Key nickname (e.g. Work PC)"
                variant="outlined"
                id="passkey-nickname"
                sx={{ width: 220 }}
              />
              <Button
                variant="outlined"
                color="secondary"
                startIcon={<FingerprintIcon />}
                onClick={async () => {
                  const input = document.getElementById('passkey-nickname') as HTMLInputElement;
                  const nickname = input.value || 'New Passkey';
                  await handleRegisterPasskey(nickname);
                  input.value = '';
                }}
                sx={{ fontWeight: 700 }}
              >
                Register
              </Button>
            </Box>
          </Box>
          <Divider sx={{ mb: 3 }} />

          {passkeys.length === 0 ? (
            <Box sx={{ py: 6, textAlign: 'center', bgcolor: 'background.default', borderRadius: 1 }}>
              <FingerprintIcon sx={{ fontSize: 48, color: 'divider', mb: 2 }} />
              <Typography color="text.secondary">
                No biometric hardware tokens registered.
              </Typography>
            </Box>
          ) : (
            <List disablePadding>
              {passkeys.map((pk, idx) => {
                // Differentiation: Hide pre-pended user-id in UI
                const displayName = pk.nickname?.includes(':')
                  ? pk.nickname.substring(pk.nickname.indexOf(':') + 1)
                  : (pk.nickname || 'Unnamed Device');

                return (
                  <ListItem
                    key={pk.credentialId}
                    divider={idx !== passkeys.length - 1}
                    secondaryAction={
                      <IconButton edge="end" aria-label="delete" onClick={() => handleDeletePasskey(pk.credentialId)}>
                        <DeleteIcon color="error" fontSize="small" />
                      </IconButton>
                    }
                    sx={{ px: 0, py: 2 }}
                  >
                    <ListItemText
                      primary={displayName}
                      primaryTypographyProps={{ fontWeight: 600 }}
                      secondary={`Last used: ${new Date(pk.lastUsedAt).toLocaleString()}`}
                      secondaryTypographyProps={{ sx: { fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem' } }}
                    />
                  </ListItem>
                );
              })}
            </List>
          )}

        </CardContent>
      </Card>

      <Box sx={{ mt: 8, display: 'flex', justifyContent: 'center' }}>
        <Button
          variant="text"
          color="inherit"
          onClick={() => { sessionStorage.clear(); window.location.href = '/'; }}
          sx={{ opacity: 0.6, '&:hover': { opacity: 1, color: 'error.main' } }}
        >
          Terminate Session
        </Button>
      </Box>
    </Container>
  );
}
