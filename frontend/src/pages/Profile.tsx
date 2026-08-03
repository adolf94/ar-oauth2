import { Box, Button, Card, CardContent, Chip, CircularProgress, Divider, List, ListItem, ListItemText, Typography, IconButton, Container, TextField, Avatar, Dialog, DialogTitle, DialogContent, DialogActions } from '@mui/material';
import { Delete as DeleteIcon, Fingerprint as FingerprintIcon, AdminPanelSettings as AdminIcon, VpnKey as VpnKeyIcon, ContentCopy as CopyIcon } from '@mui/icons-material';
import { useEffect, useState } from 'react';
import * as Passwordless from '@passwordlessdev/passwordless-client';
import api from '../api';
import ThemeSwitcher from '../components/ThemeSwitcher';
import { useNavigate } from '@tanstack/react-router';
import { saveRecentAccount } from '../storage';

interface Pat {
  id: string;
  name: string;
  scopes: string;
  createdAt: string;
  expiresAt?: string;
  lastUsedAt?: string;
}

const PASSKEY_PUBLIC_KEY = 'arapps:public:45993b214ebd42049727f9a86f56b5eb';
const p = new Passwordless.Client({
  apiKey: PASSKEY_PUBLIC_KEY,
});

interface UserProfile {
  id: string;
  email: string;
  name?: string;
  picture?: string;
  mobileNumber?: string;
  roles: string[];
  externalIdentities: Array<{
    provider: string;
    providerId: string;
    sub?: string;
    name?: string;
    email?: string;
    mobileNumber?: string;
    photoUrl?: string;
  }>;
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
  const [pats, setPats] = useState<Pat[]>([]);
  const [patName, setPatName] = useState('');
  const [patScopes, setPatScopes] = useState('');
  const [patExpiresInDays, setPatExpiresInDays] = useState('');
  const [newPatRaw, setNewPatRaw] = useState<string | null>(null);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
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
    } catch {
      console.error('Failed to fetch profile');
    }
  };

  const fetchPasskeys = async () => {
    try {
      const res = await api.get('/passkey/list');
      setPasskeys(res.data);
    } catch {
      console.error('Failed to fetch passkeys');
    }
  };

  const fetchPats = async () => {
    try {
      const res = await api.get('/pat/list');
      setPats(res.data);
    } catch {
      console.error('Failed to fetch PATs');
    }
  };

  useEffect(() => {
    const fetchData = async () => {
      try {
        await Promise.all([fetchProfile(), fetchPasskeys(), fetchPats()]);
      } catch (err) {
        // Fallback for errors or handle specifically
      } finally {
        setLoading(false);
      }
    };
    fetchData();
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
    } catch {
      console.error('Registration error');
      alert('An error occurred during registration.');
    }
  };

  const handleDeletePasskey = async (credentialId: string) => {
    if (!confirm('Are you sure you want to delete this passkey?')) return;
    try {
      await api.delete(`/passkey/${credentialId}`);
      setPasskeys(prev => prev.filter(pk => pk.credentialId !== credentialId));
    } catch {
      console.error('Delete error');
    }
  };

  const handleCreatePat = async () => {
    try {
      const res = await api.post('/pat/create', {
        name: patName,
        scopes: patScopes,
        expiresInDays: patExpiresInDays ? parseInt(patExpiresInDays) : null
      });
      setNewPatRaw(res.data.rawToken);
      setPatName('');
      setPatScopes('');
      setPatExpiresInDays('');
      fetchPats();
    } catch (err) {
      console.error('Failed to create PAT', err);
      alert('Error creating Personal Access Token');
    }
  };

  const handleDeletePat = async (id: string) => {
    if (!confirm('Are you sure you want to revoke this Personal Access Token?')) return;
    try {
      await api.delete(`/pat/${id}`);
      setPats(prev => prev.filter(p => p.id !== id));
    } catch (err) {
      console.error('Failed to delete PAT', err);
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
    } catch {
      console.error('Linking error');
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
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 3, mb: 4 }}>
            <Avatar 
              src={profile?.picture} 
              sx={{ 
                width: 100, 
                height: 100, 
                fontSize: '2rem',
                bgcolor: 'primary.main',
                boxShadow: '0 4px 12px rgba(0,0,0,0.1)'
              }}
            >
              {profile?.name?.[0] || profile?.email[0].toUpperCase()}
            </Avatar>
            <Box>
              <Typography variant="h5" fontWeight={700}>{profile?.name || 'Incomplete Profile'}</Typography>
              <Typography color="text.secondary" sx={{ fontFamily: "'JetBrains Mono', monospace" }}>{profile?.email}</Typography>
            </Box>
          </Box>

          <Box sx={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: 2 }}>
            <Typography color="text.secondary" sx={{ fontFamily: "'JetBrains Mono', monospace" }}>Name</Typography>
            <Typography fontWeight={600}>{profile?.name || '-'}</Typography>

            <Typography color="text.secondary" sx={{ fontFamily: "'JetBrains Mono', monospace" }}>Primary Email</Typography>
            <Typography fontWeight={600}>{profile?.email}</Typography>

            <Typography color="text.secondary" sx={{ fontFamily: "'JetBrains Mono', monospace" }}>Phone</Typography>
            <Typography fontWeight={600}>{profile?.mobileNumber || '-'}</Typography>

            <Typography color="text.secondary" sx={{ fontFamily: "'JetBrains Mono', monospace" }}>User ID</Typography>
            <Typography sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.81rem', color: 'text.secondary' }}>{profile?.id}</Typography>

            <Typography color="text.secondary" sx={{ fontFamily: "'JetBrains Mono', monospace" }}>System Roles</Typography>
            <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
              {profile?.roles.map(role => (
                <Chip key={role} label={role} size="small" color="primary" variant="filled" sx={{ borderRadius: 1, fontWeight: 700 }} />
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
            {(['google', 'telegram'] as const).map(pvd => {
              const identity = profile?.externalIdentities.find(i => i.provider === pvd);
              return (
                <Box key={pvd} sx={{ p: 2, bgcolor: 'background.default', borderRadius: 2, border: 1, borderColor: 'divider' }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: identity ? 1.5 : 0 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                      <Avatar 
                        src={identity?.photoUrl} 
                        sx={{ 
                          width: 32, 
                          height: 32, 
                          bgcolor: pvd === 'google' ? '#ea4335' : (pvd === 'telegram' ? '#0088cc' : 'divider'),
                          fontSize: '0.8rem'
                        }}
                      >
                        {pvd[0].toUpperCase()}
                      </Avatar>
                      <Typography fontWeight={700} sx={{ textTransform: 'capitalize' }}>{pvd}</Typography>
                      {identity ? (
                        <Chip label="Connected" size="small" color="success" sx={{ height: 20 }} />
                      ) : (
                        <Chip label="Not Linked" size="small" variant="outlined" sx={{ height: 20 }} />
                      )}
                    </Box>
                    {!identity && (
                      <Button variant="outlined" size="small" onClick={() => handleLinkAccount(pvd)}>Link {pvd}</Button>
                    )}
                  </Box>
                  
                  {identity && (
                    <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1 }}>
                       <Box>
                          <Typography variant="caption" color="text.secondary" display="block">Internal ID (Sub)</Typography>
                          <Typography variant="caption" sx={{ fontFamily: "'JetBrains Mono', monospace" }}>{identity.sub || identity.providerId}</Typography>
                       </Box>
                       <Box>
                          <Typography variant="caption" color="text.secondary" display="block">Name in Provider</Typography>
                          <Typography variant="body2">{identity.name || '-'}</Typography>
                       </Box>
                       <Box>
                          <Typography variant="caption" color="text.secondary" display="block">Email in Provider</Typography>
                          <Typography variant="body2">{identity.email || '-'}</Typography>
                       </Box>
                       <Box>
                          <Typography variant="caption" color="text.secondary" display="block">Mobile in Provider</Typography>
                          <Typography variant="body2">{identity.mobileNumber || '-'}</Typography>
                       </Box>
                    </Box>
                  )}
                </Box>
              );
            })}
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

      <Card sx={{ mb: 4, mt: 4 }}>
        <CardContent sx={{ p: 4 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Box sx={{ flex: 1, mr: 2 }}>
              <Typography variant="h6" fontWeight={700} sx={{ fontFamily: "'JetBrains Mono', monospace" }}>
                Personal Access Tokens (PATs)
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Generate long-lived tokens for API access and programmatic integrations.
              </Typography>
            </Box>
            <Button
              variant="outlined"
              color="primary"
              startIcon={<VpnKeyIcon />}
              onClick={() => setCreateDialogOpen(true)}
              sx={{ fontWeight: 700 }}
            >
              Generate Token
            </Button>
          </Box>
          <Divider sx={{ mb: 3 }} />

          {pats.length === 0 ? (
            <Box sx={{ py: 6, textAlign: 'center', bgcolor: 'background.default', borderRadius: 1 }}>
              <VpnKeyIcon sx={{ fontSize: 48, color: 'divider', mb: 2 }} />
              <Typography color="text.secondary">
                No active personal access tokens.
              </Typography>
            </Box>
          ) : (
            <List disablePadding>
              {pats.map((pat, idx) => (
                <ListItem
                  key={pat.id}
                  divider={idx !== pats.length - 1}
                  secondaryAction={
                    <IconButton edge="end" aria-label="delete" onClick={() => handleDeletePat(pat.id)}>
                      <DeleteIcon color="error" fontSize="small" />
                    </IconButton>
                  }
                  sx={{ px: 0, py: 2 }}
                >
                  <ListItemText
                    primary={pat.name}
                    primaryTypographyProps={{ fontWeight: 600 }}
                    secondary={
                      <Box component="span" display="block">
                        <Box component="span" display="block" sx={{ mt: 0.5 }}>
                          Scopes: {pat.scopes ? pat.scopes.split(' ').map(s => (
                            <Chip key={s} label={s} size="small" variant="outlined" sx={{ mr: 0.5, height: 18, fontSize: '0.65rem' }} />
                          )) : <Chip label="None" size="small" variant="outlined" sx={{ mr: 0.5, height: 18, fontSize: '0.65rem' }} />}
                        </Box>
                        <Box component="span" display="block" sx={{ mt: 0.5, fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem' }}>
                          Created: {new Date(pat.createdAt).toLocaleDateString()}
                          {pat.expiresAt && ` | Expires: ${new Date(pat.expiresAt).toLocaleDateString()}`}
                          {pat.lastUsedAt && ` | Last Used: ${new Date(pat.lastUsedAt).toLocaleString()}`}
                        </Box>
                      </Box>
                    }
                  />
                </ListItem>
              ))}
            </List>
          )}
        </CardContent>
      </Card>

      {/* Dialog for creating a new PAT */}
      <Dialog open={createDialogOpen} onClose={() => { setCreateDialogOpen(false); setNewPatRaw(null); }} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ fontWeight: 700 }}>Generate Personal Access Token</DialogTitle>
        <DialogContent sx={{ pt: 1 }}>
          {newPatRaw ? (
            <Box>
              <Typography variant="body2" color="warning.main" fontWeight={700} gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                ⚠️ Warning: Make sure to copy this token now. It will not be shown again!
              </Typography>
              <Box sx={{ 
                p: 2, 
                bgcolor: 'background.default', 
                borderRadius: 1, 
                border: 1, 
                borderColor: 'divider',
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '0.9rem',
                wordBreak: 'break-all',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 2,
                my: 2
              }}>
                <code>{newPatRaw}</code>
                <IconButton onClick={() => { navigator.clipboard.writeText(newPatRaw); alert('Copied to clipboard!'); }}>
                  <CopyIcon fontSize="small" />
                </IconButton>
              </Box>
            </Box>
          ) : (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
              <TextField
                label="Token Name"
                fullWidth
                placeholder="e.g. CI/CD pipeline, Script access"
                value={patName}
                onChange={e => setPatName(e.target.value)}
              />
              <TextField
                label="Scopes (Space-separated)"
                fullWidth
                placeholder="openid profile offline_access"
                value={patScopes}
                onChange={e => setPatScopes(e.target.value)}
              />
              <TextField
                label="Expires in (Days - Optional)"
                fullWidth
                type="number"
                placeholder="Never"
                value={patExpiresInDays}
                onChange={e => setPatExpiresInDays(e.target.value)}
              />
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 3 }}>
          {newPatRaw ? (
            <Button variant="contained" onClick={() => { setCreateDialogOpen(false); setNewPatRaw(null); }}>Done</Button>
          ) : (
            <>
              <Button onClick={() => setCreateDialogOpen(false)}>Cancel</Button>
              <Button variant="contained" onClick={handleCreatePat} disabled={!patName}>Generate</Button>
            </>
          )}
        </DialogActions>
      </Dialog>

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
