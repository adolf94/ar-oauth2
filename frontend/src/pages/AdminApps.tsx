import { Box, Button, Typography, Paper, Stack, TextField, Autocomplete, Chip, IconButton, Tooltip, CircularProgress, Dialog, DialogTitle, DialogContent, DialogActions } from '@mui/material';
import { Table, TableBody, TableCell, TableContainer, TableHead, TableRow } from '@mui/material';
import { Delete as DeleteIcon, Edit as EditIcon, Key as KeyIcon, Add as AddIcon } from '@mui/icons-material';
import { useState, useEffect } from 'react';
import api from '../api';

interface AppModel {
  id: string;
  clientId: string;
  redirectUris: string[];
  allowedScopes: string[];
  clientSecrets?: { id: string; createdAt: string; description: string }[];
}

export default function AdminApps() {
  const [apps, setApps] = useState<AppModel[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [editingApp, setEditingApp] = useState<AppModel | null>(null);
  const [newApp, setNewApp] = useState({ clientId: '', redirectUris: [] as string[], allowedScopes: ['openid', 'profile'] });
  const [submitting, setSubmitting] = useState(false);
  const [generatedSecret, setGeneratedSecret] = useState<string | null>(null);
  const [showSecretDialog, setShowSecretDialog] = useState(false);
  
  const [manageSecretsApp, setManageSecretsApp] = useState<AppModel | null>(null);
  const [secretsDialogOpen, setSecretsDialogOpen] = useState(false);
  const [secretDescription, setSecretDescription] = useState('New Secret');
  const [addingSecret, setAddingSecret] = useState(false);

  const fetchApps = () => {
    setLoading(true);
    api.get('/manage/clients')
      .then(res => {
        setApps(res.data);
        setLoading(false);
      })
      .catch(err => {
        console.error('Error fetching apps:', err);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchApps();
  }, []);

  const handleOpenCreate = () => {
    setEditingApp(null);
    setNewApp({ clientId: '', redirectUris: [], allowedScopes: ['openid', 'profile'] });
    setOpen(true);
  };

  const handleOpenEdit = (app: AppModel) => {
    setEditingApp(app);
    setNewApp({ 
      clientId: app.clientId, 
      redirectUris: [...(app.redirectUris || [])], 
      allowedScopes: [...(app.allowedScopes || [])] 
    });
    setOpen(true);
  };

  const handleSubmit = async () => {
    setSubmitting(true);
    try {
      if (editingApp) {
        await api.put(`/manage/clients/${editingApp.id}`, {
          redirectUris: newApp.redirectUris,
          allowedScopes: newApp.allowedScopes
        });
      } else {
        const response = await api.post('/manage/clients', {
          clientId: newApp.clientId,
          redirectUris: newApp.redirectUris,
          allowedScopes: newApp.allowedScopes
        });
        setGeneratedSecret(response.data.plainSecret);
        setShowSecretDialog(true);
      }
      setOpen(false);
      fetchApps();
    } catch (err: any) {
      console.error('Failed to save app:', err);
      alert(`Error: ${err.response?.data || err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this application? This action cannot be undone.')) return;
    try {
      await api.delete(`/manage/clients/${id}`);
      fetchApps();
    } catch (err) {
      console.error('Delete error', err);
    }
  };

  const handleOpenSecrets = (app: AppModel) => {
    setManageSecretsApp(app);
    setSecretsDialogOpen(true);
  };

  const handleAddSecret = async () => {
    if (!manageSecretsApp) return;
    setAddingSecret(true);
    try {
      const response = await api.post(`/manage/clients/${manageSecretsApp.id}/secrets`, {
        description: secretDescription
      });
      setGeneratedSecret(response.data.plainSecret);
      setShowSecretDialog(true);
      setSecretsDialogOpen(false);
      fetchApps();
    } catch (err: any) {
      console.error('Failed to add secret:', err);
      alert('Failed to add secret');
    } finally {
      setAddingSecret(false);
      setSecretDescription('New Secret');
    }
  };

  const handleDeleteSecret = async (secretId: string) => {
    if (!manageSecretsApp) return;
    if (!confirm('Are you sure you want to delete this secret? Applications using it will stop working immediately.')) return;
    
    try {
      await api.delete(`/manage/clients/${manageSecretsApp.id}/secrets/${secretId}`);
      // Refresh local state or re-fetch
      const updatedApps = apps.map(app => {
        if (app.id === manageSecretsApp.id) {
          return {
            ...app,
            clientSecrets: app.clientSecrets?.filter(s => s.id !== secretId)
          };
        }
        return app;
      });
      setApps(updatedApps);
      setManageSecretsApp(updatedApps.find(a => a.id === manageSecretsApp.id) || null);
    } catch (err) {
      console.error('Failed to delete secret:', err);
      alert('Failed to delete secret');
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
        <Typography variant="h4" fontWeight={700} sx={{ letterSpacing: -1 }}>
          Application <Box component="span" sx={{ color: 'primary.main' }}>Registry</Box>
        </Typography>
        <Button 
          variant="contained" 
          onClick={handleOpenCreate} 
          startIcon={<AddIcon />} 
          sx={{ fontFamily: "'JetBrains Mono', monospace" }}
        >
          Register New App
        </Button>
      </Box>

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ fontWeight: 'bold' }}>
          {editingApp ? 'Edit Application' : 'Register New Application'}
        </DialogTitle>
        <DialogContent>
          <Stack spacing={3} sx={{ mt: 1 }}>
            <TextField
              label="Client ID"
              fullWidth
              disabled={!!editingApp}
              value={newApp.clientId}
              onChange={(e) => setNewApp({ ...newApp, clientId: e.target.value })}
              placeholder="e.g. my-awesome-app"
              helperText={editingApp ? "Client ID cannot be changed" : ""}
            />
            
            <Autocomplete
              multiple
              freeSolo
              options={[]}
              value={newApp.redirectUris}
              onChange={(_, newValue) => setNewApp({ ...newApp, redirectUris: newValue as string[] })}
              renderTags={(value: string[], getTagProps) =>
                value.map((option: string, index: number) => (
                  <Chip variant="filled" label={option} {...getTagProps({ index })} size="small" color="primary" />
                ))
              }
              renderInput={(params) => (
                <TextField
                  {...params}
                  variant="outlined"
                  label="Redirect URIs"
                  placeholder="Type URI and press Enter"
                  helperText="Enter all valid callback URLs for this application"
                />
              )}
            />

            <Autocomplete
              multiple
              freeSolo
              options={['openid', 'profile', 'email', 'offline_access', 'admin', 'manage']}
              value={newApp.allowedScopes}
              onChange={(_, newValue) => setNewApp({ ...newApp, allowedScopes: newValue as string[] })}
              renderTags={(value: string[], getTagProps) =>
                value.map((option: string, index: number) => (
                  <Chip variant="filled" label={option} {...getTagProps({ index })} size="small" color="primary" />
                ))
              }
              renderInput={(params) => (
                <TextField
                  {...params}
                  variant="outlined"
                  label="Allowed Scopes"
                  placeholder="openid, profile, etc."
                />
              )}
            />
          </Stack>
        </DialogContent>
        <DialogActions sx={{ p: 3 }}>
          <Button onClick={() => setOpen(false)} color="inherit">Cancel</Button>
          <Button
            variant="contained"
            onClick={handleSubmit}
            disabled={submitting || !newApp.clientId}
            sx={{ px: 4, borderRadius: 2 }}
          >
            {submitting ? <CircularProgress size={24} color="inherit" /> : editingApp ? 'Update App' : 'Register App'}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={showSecretDialog} onClose={() => setShowSecretDialog(false)}>
        <DialogTitle sx={{ color: 'secondary.main', fontWeight: 'bold' }}>
          Secret Generated Successfully!
        </DialogTitle>
        <DialogContent>
          <Typography variant="body1" gutterBottom>
            Please copy this secret and store it securely. We will <strong>NOT</strong> show it to you again.
          </Typography>
          <Paper 
            variant="outlined" 
            sx={{ 
              p: 2, 
              mt: 2, 
              bgcolor: 'background.paper', 
              fontFamily: 'monospace', 
              fontSize: '1.1rem',
              color: 'primary.light',
              wordBreak: 'break-all'
            }}
          >
            {generatedSecret}
          </Paper>
        </DialogContent>
        <DialogActions sx={{ p: 3 }}>
          <Button 
            variant="contained" 
            fullWidth 
            onClick={() => {
              navigator.clipboard.writeText(generatedSecret || '');
              setShowSecretDialog(false);
            }}
          >
            Copy & Close
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={secretsDialogOpen} onClose={() => setSecretsDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle sx={{ fontWeight: 'bold' }}>
          Manage Secrets: {manageSecretsApp?.clientId}
        </DialogTitle>
        <DialogContent>
          <TableContainer component={Paper} variant="outlined" sx={{ mt: 2 }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell><strong>Description</strong></TableCell>
                  <TableCell><strong>Created At</strong></TableCell>
                  <TableCell align="right"><strong>Actions</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {manageSecretsApp?.clientSecrets?.map((secret) => (
                  <TableRow key={secret.id}>
                    <TableCell>{secret.description}</TableCell>
                    <TableCell>{new Date(secret.createdAt).toLocaleString()}</TableCell>
                    <TableCell align="right">
                      <IconButton size="small" color="error" onClick={() => handleDeleteSecret(secret.id)}>
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
                {(!manageSecretsApp?.clientSecrets || manageSecretsApp.clientSecrets.length === 0) && (
                  <TableRow>
                    <TableCell colSpan={3} align="center" sx={{ py: 3 }}>
                      No secrets found. This client won't be able to authenticate.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>

          <Box sx={{ mt: 4, pt: 2, borderTop: 1, borderColor: 'divider' }}>
            <Typography variant="subtitle2" gutterBottom fontWeight="bold">Add New Secret</Typography>
            <Stack direction="row" spacing={2} alignItems="flex-start">
              <TextField 
                size="small" 
                fullWidth 
                label="Description" 
                value={secretDescription}
                onChange={(e) => setSecretDescription(e.target.value)}
                placeholder="e.g. Production Key, Jenkins Secret"
              />
              <Button 
                variant="contained" 
                color="secondary" 
                onClick={handleAddSecret}
                disabled={addingSecret || !secretDescription}
                sx={{ whiteSpace: 'nowrap' }}
              >
                {addingSecret ? <CircularProgress size={24} /> : "Generate Secret"}
              </Button>
            </Stack>
          </Box>
        </DialogContent>
        <DialogActions sx={{ p: 3 }}>
          <Button onClick={() => setSecretsDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', p: 5 }}>
          <CircularProgress />
        </Box>
      ) : (
        <TableContainer component={Paper} elevation={2} sx={{ borderRadius: 2 }}>
          <Table sx={{ minWidth: 650 }}>
            <TableHead sx={{ bgcolor: 'action.hover' }}>
              <TableRow>
                <TableCell><strong>Client ID</strong></TableCell>
                <TableCell><strong>Configuration</strong></TableCell>
                <TableCell align="right"><strong>Actions</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {apps.map((row) => (
                <TableRow key={row.clientId} sx={{ '&:hover': { bgcolor: 'action.selected' } }}>
                  <TableCell component="th" scope="row">
                    <Typography variant="subtitle1" fontWeight="bold" color="primary">
                      {row.clientId}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {row.clientSecrets?.length || 0} active secrets
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 1 }}>
                      {row.allowedScopes?.map(s => <Chip key={s} label={s} size="small" variant="outlined" />)}
                    </Box>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                      {row.redirectUris?.map(uri => (
                        <Typography key={uri} variant="caption" sx={{ display: 'block', color: 'text.secondary', fontFamily: 'monospace' }}>
                          • {uri}
                        </Typography>
                      ))}
                    </Box>
                  </TableCell>
                  <TableCell align="right">
                    <Stack direction="row" spacing={1} justifyContent="flex-end">
                      <Tooltip title="Manage Secrets">
                        <IconButton size="small" color="secondary" onClick={() => handleOpenSecrets(row)}>
                          <KeyIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Edit Application">
                        <IconButton size="small" color="primary" onClick={() => handleOpenEdit(row)}>
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete Application">
                        <IconButton size="small" color="error" onClick={() => handleDelete(row.id)}>
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </Stack>
                  </TableCell>
                </TableRow>
              ))}
              {apps.length === 0 && (
                <TableRow>
                  <TableCell colSpan={3} align="center" sx={{ py: 10 }}>
                    <Typography color="text.secondary">No applications registered.</Typography>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Box>
  );
}
