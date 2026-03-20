import { Box, Button, Card, CardContent, Chip, CircularProgress, Divider, List, ListItem, ListItemText, Typography, IconButton, Container, TextField } from '@mui/material';
import { Delete as DeleteIcon, Fingerprint as FingerprintIcon, AdminPanelSettings as AdminIcon, Android as AndroidIcon } from '@mui/icons-material';
import { useEffect, useState } from 'react';
import * as Passwordless from '@passwordlessdev/passwordless-client';
import api from '../api';
import ThemeSwitcher from '../components/ThemeSwitcher';
import { useNavigate } from '@tanstack/react-router';

const PASSKEY_PUBLIC_KEY = 'arapps:public:45993b214ebd42049727f9a86f56b5eb';
const p = new Passwordless.Client({
  apiKey: PASSKEY_PUBLIC_KEY,
});

interface UserProfile {
  id: string;
  email: string;
  roles: string[];
  automateDeviceName?: string;
  hasAutomateSecret: boolean;
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
  
  // Automate Settings State
  const [automateSecret, setAutomateSecret] = useState('');
  const [automateDevice, setAutomateDevice] = useState('');
  const [savingAutomate, setSavingAutomate] = useState(false);

  const navigate = useNavigate();

  const fetchProfile = async () => {
    try {
      const res = await api.get('/profile');
      setProfile(res.data);
      if (res.data.automateDeviceName) {
        setAutomateDevice(res.data.automateDeviceName);
      }
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

  const handleRegisterPasskey = async () => {
    try {
      const res = await api.post('/passkey/register/start');
      const registerToken = res.data.token;
      const { error } = await p.register(registerToken, 'My New Device');
      
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

  const handleSaveAutomate = async () => {
    setSavingAutomate(true);
    try {
      await api.post('/profile/automate', {
        secret: automateSecret || undefined, // Send only if not empty
        deviceName: automateDevice
      });
      alert('Automate settings saved successfully!');
      setAutomateSecret(''); // Clear secret field after save
      fetchProfile();
    } catch (err) {
      console.error('Save error', err);
      alert('Failed to save Automate settings.');
    } finally {
      setSavingAutomate(false);
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
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}>
            <AndroidIcon color="success" />
            <Typography variant="h6" fontWeight={700} sx={{ fontFamily: "'JetBrains Mono', monospace" }}>
              Llamalabs Automate
            </Typography>
          </Box>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Enable push notifications for authentication data via Automate Cloud Receive.
          </Typography>
          <Divider sx={{ mb: 3 }} />
          
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
              <TextField
                label="Automate Secret"
                type="password"
                variant="outlined"
                fullWidth
                value={automateSecret}
                onChange={(e) => setAutomateSecret(e.target.value)}
                placeholder={profile?.hasAutomateSecret ? '•••••••• (Saved)' : 'Enter Automate Secret'}
                helperText="Required for Cloud Receive push"
                InputLabelProps={{ shrink: true }}
              />
              <TextField
                label="Device Name"
                variant="outlined"
                fullWidth
                value={automateDevice}
                onChange={(e) => setAutomateDevice(e.target.value)}
                placeholder="e.g. Pixel 8"
                helperText="Registered device name in Automate"
              />
            </Box>
            <Box sx={{ display: 'flex', justifyContent: 'flex-end' }}>
              <Button 
                variant="contained" 
                color="success" 
                onClick={handleSaveAutomate}
                disabled={savingAutomate || !automateDevice}
                sx={{ fontWeight: 700, px: 4 }}
              >
                {savingAutomate ? 'Saving...' : 'Save Automate Settings'}
              </Button>
            </Box>
          </Box>
        </CardContent>
      </Card>

      <Card>
        <CardContent sx={{ p: 4 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Typography variant="h6" fontWeight={700} sx={{ fontFamily: "'JetBrains Mono', monospace" }}>
              Passkeys (WebAuthn)
            </Typography>
            <Button 
                variant="outlined" 
                color="secondary"
                startIcon={<FingerprintIcon />} 
                onClick={handleRegisterPasskey}
                sx={{ fontWeight: 700 }}
            >
              Register Passkey
            </Button>
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
              {passkeys.map((pk, idx) => (
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
                    primary={pk.nickname || 'Unnamed Device'} 
                    primaryTypographyProps={{ fontWeight: 600 }}
                    secondary={`Last used: ${new Date(pk.lastUsedAt).toLocaleString()}`}
                    secondaryTypographyProps={{ sx: { fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem' } }}
                  />
                </ListItem>
              ))}
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
