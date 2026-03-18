import { Box, Button, Typography, Paper, Stack, TextField, Autocomplete, Chip, IconButton, Tooltip, CircularProgress, Dialog, DialogTitle, DialogContent, DialogActions, FormControlLabel, Switch, Tabs, Tab } from '@mui/material';
import { Table, TableBody, TableCell, TableContainer, TableHead, TableRow } from '@mui/material';
import { Delete as DeleteIcon, Edit as EditIcon, Key as KeyIcon, Add as AddIcon, Public as PublicIcon, Lock as LockIcon, Shield as ShieldIcon, CheckCircle as CheckCircleIcon, Person as PersonIcon, Sync as SyncIcon } from '@mui/icons-material';
import { useState, useEffect } from 'react';
import api from '../api';

interface AppModel {
  id: string;
  clientId: string;
  redirectUris: string[];
  allowedScopes: string[];
  clientSecrets?: any[];
  roleCount?: number;
  scopeCount?: number;
  autoGrantCount?: number;
  trustCount?: number;
  applicationScopes?: { id: string; name: string; fullScopeName: string; description?: string }[];
}

export default function AdminApps() {
  const [apps, setApps] = useState<AppModel[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [editingApp, setEditingApp] = useState<AppModel | null>(null);
  const [newApp, setNewApp] = useState({ clientId: '', redirectUris: [] as string[], allowedScopes: ['openid', 'profile'], isPublic: false });
  const [submitting, setSubmitting] = useState(false);
  const [generatedSecret, setGeneratedSecret] = useState<string | null>(null);
  const [showSecretDialog, setShowSecretDialog] = useState(false);
  
  const [manageSecretsApp, setManageSecretsApp] = useState<AppModel | null>(null);
  const [secretsDialogOpen, setSecretsDialogOpen] = useState(false);
  const [secretDescription, setSecretDescription] = useState('New Secret');
  const [addingSecret, setAddingSecret] = useState(false);

  const [manageScopesApp, setManageScopesApp] = useState<AppModel | null>(null);
  const [scopesDialogOpen, setScopesDialogOpen] = useState(false);
  const [newScope, setNewScope] = useState({ name: '', description: '', isAdminApproved: false });
  const [addingScope, setAddingScope] = useState(false);
  const [appScopes, setAppScopes] = useState<any[]>([]);

  const [appRoles, setAppRoles] = useState<any[]>([]);
  const [newRole, setNewRole] = useState({ name: '', description: '' });
  const [addingRole, setAddingRole] = useState(false);
  
  const [appTrusts, setAppTrusts] = useState<any[]>([]);
  const [newTrust, setNewTrust] = useState({ targetClientId: '', scopeName: '' });
  const [addingTrust, setAddingTrust] = useState(false);
  const [targetAppScopes, setTargetAppScopes] = useState<any[]>([]);

  const [activeTab, setActiveTab] = useState(0);

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
    setNewApp({ clientId: '', redirectUris: [], allowedScopes: ['openid', 'profile'], isPublic: false });
    setOpen(true);
  };

  const handleOpenEdit = (app: AppModel) => {
    setEditingApp(app);
    setNewApp({ 
      clientId: app.clientId, 
      redirectUris: [...(app.redirectUris || [])], 
      allowedScopes: [...(app.allowedScopes || [])],
      isPublic: !app.clientSecrets || app.clientSecrets.length === 0
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
          allowedScopes: newApp.allowedScopes,
          isPublic: newApp.isPublic
        });
        if (response.data.plainSecret) {
          setGeneratedSecret(response.data.plainSecret);
          setShowSecretDialog(true);
        }
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

  const handleOpenScopes = async (app: AppModel) => {
    setManageScopesApp(app);
    setScopesDialogOpen(true);
    setAppScopes([]);
    setAppRoles([]);
    setAppTrusts([]);
    setActiveTab(0);
    try {
      const res = await api.get(`/manage/scopes?client_id=${app.clientId}`);
      setAppScopes(res.data);
      const rolesRes = await api.get(`/manage/roles?client_id=${app.clientId}`);
      setAppRoles(rolesRes.data);
      const trustRes = await api.get(`/manage/trusts?client_id=${app.clientId}`);
      setAppTrusts(trustRes.data);
    } catch (err) {
      console.error('Error fetching capabilities:', err);
    }
  };

  const handleTargetAppChange = async (clientId: string) => {
    setNewTrust({ ...newTrust, targetClientId: clientId, scopeName: '' });
    setTargetAppScopes([]);
    if (clientId) {
      try {
        const res = await api.get(`/manage/scopes?client_id=${clientId}`);
        setTargetAppScopes(res.data);
      } catch (err) {
        console.error('Error fetching target scopes', err);
      }
    }
  };

  const handleAddTrust = async () => {
    if (!manageScopesApp) return;
    setAddingTrust(true);
    try {
      await api.post('/manage/trusts', {
        requestingClientId: manageScopesApp.clientId,
        targetClientId: newTrust.targetClientId,
        scopeName: newTrust.scopeName
      });
      setNewTrust({ targetClientId: '', scopeName: '' });
      // Refresh
      const res = await api.get(`/manage/trusts?client_id=${manageScopesApp.clientId}`);
      setAppTrusts(res.data);
    } catch (err: any) {
      alert(err.response?.data || 'Failed to add trust');
    } finally {
      setAddingTrust(false);
    }
  };

  const handleDeleteTrust = async (id: string) => {
    if (!confirm('Delete this trust relationship?')) return;
    try {
      await api.delete(`/manage/trusts/${id}?client_id=${manageScopesApp?.clientId}`);
      setAppTrusts(appTrusts.filter(t => t.id !== id));
    } catch (err) {
      alert('Failed to delete trust');
    }
  };

  const handleAddRole = async () => {
    if (!manageScopesApp) return;
    setAddingRole(true);
    try {
      await api.post('/manage/roles', {
        clientId: manageScopesApp.clientId,
        name: newRole.name,
        description: newRole.description
      });
      setNewRole({ name: '', description: '' });
      // Refresh
      const res = await api.get(`/manage/roles?client_id=${manageScopesApp.clientId}`);
      setAppRoles(res.data);
    } catch (err: any) {
      alert(err.response?.data || 'Failed to add role');
    } finally {
      setAddingRole(false);
    }
  };

  const handleDeleteRole = async (id: string) => {
    if (!confirm('Delete this role?')) return;
    try {
      await api.delete(`/manage/roles/${id}?client_id=${manageScopesApp?.clientId}`);
      setAppRoles(appRoles.filter(r => r.id !== id));
    } catch (err) {
      alert('Failed to delete role');
    }
  };

  const handleAddScope = async () => {
    if (!manageScopesApp) return;
    setAddingScope(true);
    try {
      await api.post('/manage/scopes', {
        clientId: manageScopesApp.clientId,
        name: newScope.name,
        description: newScope.description,
        isAdminApproved: newScope.isAdminApproved
      });
      setNewScope({ name: '', description: '', isAdminApproved: false });
      // Refresh
      const res = await api.get(`/manage/scopes?client_id=${manageScopesApp.clientId}`);
      setAppScopes(res.data);
    } catch (err: any) {
      alert(err.response?.data || 'Failed to add scope');
    } finally {
      setAddingScope(false);
    }
  };

  const handleDeleteScope = async (id: string) => {
    if (!confirm('Delete this scope?')) return;
    try {
      await api.delete(`/manage/scopes/${id}`);
      setAppScopes(appScopes.filter(s => s.id !== id));
    } catch (err) {
      alert('Failed to delete scope');
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
                />
              )}
            />

            {!editingApp && (
              <FormControlLabel
                control={
                  <Switch 
                    checked={newApp.isPublic} 
                    onChange={(e) => setNewApp({ ...newApp, isPublic: e.target.checked })} 
                    color="primary"
                  />
                }
                label={
                  <Box>
                    <Typography variant="body1">Public Application</Typography>
                    <Typography variant="caption" color="text.secondary">
                      For SPAs or Mobile Apps. No client secret required, uses PKCE.
                    </Typography>
                  </Box>
                }
              />
            )}

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
                <TableCell><strong>Capabilities</strong></TableCell>
                <TableCell align="right"><strong>Actions</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {apps.map((row) => (
                <TableRow key={row.clientId} sx={{ '&:hover': { bgcolor: 'action.selected' } }}>
                  <TableCell component="th" scope="row">
                    <Typography variant="subtitle1" fontWeight="bold" color="primary" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      {row.clientId}
                      {(!row.clientSecrets || row.clientSecrets.length === 0) ? (
                        <Tooltip title="Public Client (PKCE)">
                          <PublicIcon sx={{ fontSize: 16, color: 'info.main' }} />
                        </Tooltip>
                      ) : (
                        <Tooltip title="Confidential Client (Secret)">
                          <LockIcon sx={{ fontSize: 16, color: 'warning.main' }} />
                        </Tooltip>
                      )}
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
                  <TableCell>
                    <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                      {row.roleCount !== undefined && row.roleCount > 0 && (
                        <Tooltip title="Defined Application Roles">
                          <Chip size="small" label={`${row.roleCount} Roles`} color="info" variant="outlined" sx={{ height: 20, fontSize: '0.7rem' }} />
                        </Tooltip>
                      )}
                      {row.scopeCount !== undefined && row.scopeCount > 0 && (
                        <Tooltip title="Custom API Scopes">
                          <Chip size="small" label={`${row.scopeCount} Scopes`} color="secondary" variant="outlined" sx={{ height: 20, fontSize: '0.7rem' }} />
                        </Tooltip>
                      )}
                      {row.autoGrantCount !== undefined && row.autoGrantCount > 0 && (
                        <Tooltip title="Admin Approved (Auto-granted)">
                          <Chip size="small" label={`${row.autoGrantCount} Auto`} color="success" variant="outlined" sx={{ height: 20, fontSize: '0.7rem' }} />
                        </Tooltip>
                      )}
                      {row.trustCount !== undefined && row.trustCount > 0 && (
                        <Tooltip title="Cross-App trust permissions">
                          <Chip size="small" label={`${row.trustCount} Trusts`} color="primary" variant="outlined" sx={{ height: 20, fontSize: '0.7rem' }} icon={<SyncIcon sx={{ fontSize: '10px !important' }} />} />
                        </Tooltip>
                      )}
                      {(!row.roleCount && !row.scopeCount && !row.trustCount) && (
                        <Typography variant="caption" color="text.disabled">None</Typography>
                      )}
                    </Stack>
                  </TableCell>
                  <TableCell align="right">
                    <Stack direction="row" spacing={1} justifyContent="flex-end">
                      <Tooltip title="Manage Scopes">
                        <IconButton size="small" color="info" onClick={() => handleOpenScopes(row)}>
                          <ShieldIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
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

      {/* Scopes Dialog */}
      <Dialog open={scopesDialogOpen} onClose={() => setScopesDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle sx={{ fontWeight: 'bold' }}>
          App Capabilities: {manageScopesApp?.clientId}
        </DialogTitle>
        <DialogContent>
          <Tabs value={activeTab} onChange={(_, val) => setActiveTab(val)} sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
            <Tab label="OIDC Scopes" />
            <Tab label="Application Roles" />
            <Tab label="Cross-App Permissions" />
          </Tabs>

          {activeTab === 0 && (
            <Box>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Define custom API scopes for this application. These can be requested using <code>api://{manageScopesApp?.clientId}/[scope-name]</code>
              </Typography>
              
              <TableContainer component={Paper} variant="outlined" sx={{ mt: 2 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell><strong>Scope Name</strong></TableCell>
                      <TableCell><strong>Full Identifier</strong></TableCell>
                      <TableCell><strong>Type</strong></TableCell>
                      <TableCell><strong>Description</strong></TableCell>
                      <TableCell align="right"><strong>Actions</strong></TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {appScopes.map((scope) => (
                      <TableRow key={scope.id}>
                        <TableCell><code>{scope.name}</code></TableCell>
                        <TableCell><Typography variant="caption" sx={{ fontFamily: 'monospace' }}>{scope.fullScopeName}</Typography></TableCell>
                        <TableCell>
                          {scope.isAdminApproved ? (
                            <Chip size="small" label="Auto-grant" color="success" icon={<CheckCircleIcon sx={{ fontSize: '14px !important' }} />} />
                          ) : (
                            <Chip size="small" label="Manual" variant="outlined" icon={<PersonIcon sx={{ fontSize: '14px !important' }} />} />
                          )}
                        </TableCell>
                        <TableCell>{scope.description}</TableCell>
                        <TableCell align="right">
                          <IconButton size="small" color="error" onClick={() => handleDeleteScope(scope.id)}>
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                    {appScopes.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={4} align="center" sx={{ py: 3 }}>No custom scopes defined.</TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </TableContainer>

              <Box sx={{ mt: 4, pt: 2, borderTop: 1, borderColor: 'divider' }}>
                <Typography variant="subtitle2" gutterBottom fontWeight="bold">Add Custom Scope</Typography>
                <Stack spacing={2}>
                  <TextField 
                    size="small" 
                    fullWidth 
                    label="Scope Name" 
                    value={newScope.name}
                    onChange={(e) => setNewScope({ ...newScope, name: e.target.value })}
                    placeholder="e.g. read:profile, write:data"
                  />
                  <TextField 
                    size="small" 
                    fullWidth 
                    label="Description" 
                    value={newScope.description}
                    onChange={(e) => setNewScope({ ...newScope, description: e.target.value })}
                    placeholder="Optional description"
                  />
                  <FormControlLabel
                    control={
                      <Switch 
                        checked={newScope.isAdminApproved} 
                        onChange={(e) => setNewScope({ ...newScope, isAdminApproved: e.target.checked })} 
                      />
                    }
                    label={
                      <Box>
                        <Typography variant="body2">Admin Approved (Auto-grant)</Typography>
                        <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
                          If enabled, this scope is automatically given to ALL users of this application.
                        </Typography>
                      </Box>
                    }
                  />
                  <Button 
                    variant="contained" 
                    onClick={handleAddScope}
                    disabled={addingScope || !newScope.name}
                  >
                    {addingScope ? <CircularProgress size={24} /> : "Add Scope"}
                  </Button>
                </Stack>
              </Box>
            </Box>
          )}

          {activeTab === 1 && (
            <Box>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Define discrete Roles available for this specific application (e.g., 'Admin', 'Editor', 'Viewer').
              </Typography>
              
              <TableContainer component={Paper} variant="outlined" sx={{ mt: 2 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell><strong>Role Name</strong></TableCell>
                      <TableCell><strong>Description</strong></TableCell>
                      <TableCell align="right"><strong>Actions</strong></TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {appRoles.map((role) => (
                      <TableRow key={role.id}>
                        <TableCell><code>{role.name}</code></TableCell>
                        <TableCell>{role.description}</TableCell>
                        <TableCell align="right">
                          <IconButton size="small" color="error" onClick={() => handleDeleteRole(role.id)}>
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                    {appRoles.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={3} align="center" sx={{ py: 3 }}>No roles defined for this app.</TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </TableContainer>

              <Box sx={{ mt: 4, pt: 2, borderTop: 1, borderColor: 'divider' }}>
                <Typography variant="subtitle2" gutterBottom fontWeight="bold">Define New Role</Typography>
                <Stack spacing={2}>
                  <TextField 
                    size="small" 
                    fullWidth 
                    label="Role Name" 
                    value={newRole.name}
                    onChange={(e) => setNewRole({ ...newRole, name: e.target.value })}
                    placeholder="e.g. Admin, Editor"
                  />
                  <TextField 
                    size="small" 
                    fullWidth 
                    label="Description" 
                    value={newRole.description}
                    onChange={(e) => setNewRole({ ...newRole, description: e.target.value })}
                  />
                  <Button 
                    variant="contained" 
                    onClick={handleAddRole}
                    disabled={addingRole || !newRole.name}
                  >
                    {addingRole ? <CircularProgress size={24} /> : "Define Role"}
                  </Button>
                </Stack>
              </Box>
            </Box>
          )}

          {activeTab === 2 && (
            <Box>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Authorize this application to request specific scopes belonging to OTHER applications.
              </Typography>
              
              <TableContainer component={Paper} variant="outlined" sx={{ mt: 2 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell><strong>Target Application</strong></TableCell>
                      <TableCell><strong>Authorized Scope</strong></TableCell>
                      <TableCell align="right"><strong>Actions</strong></TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {appTrusts.map((trust) => (
                      <TableRow key={trust.id}>
                        <TableCell><Chip size="small" label={trust.targetClientId} icon={<SyncIcon sx={{ fontSize: '14px !important' }} />} /></TableCell>
                        <TableCell><code>api://{trust.targetClientId}/{trust.scopeName}</code></TableCell>
                        <TableCell align="right">
                          <IconButton size="small" color="error" onClick={() => handleDeleteTrust(trust.id)}>
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                    {appTrusts.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={3} align="center" sx={{ py: 3 }}>No cross-app permissions defined.</TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </TableContainer>

              <Box sx={{ mt: 4, pt: 2, borderTop: 1, borderColor: 'divider' }}>
                <Typography variant="subtitle2" gutterBottom fontWeight="bold">Authorize New Permission</Typography>
                <Stack direction="row" spacing={2} alignItems="flex-start">
                  <Autocomplete
                    size="small"
                    sx={{ minWidth: 200 }}
                    options={apps.filter(a => a.clientId !== manageScopesApp?.clientId).map(a => a.clientId)}
                    value={newTrust.targetClientId}
                    onChange={(_, val) => handleTargetAppChange(val || '')}
                    renderInput={(params) => <TextField {...params} label="Target Client" />}
                  />
                  <Autocomplete
                    size="small"
                    fullWidth
                    options={targetAppScopes.map(s => s.name)}
                    value={newTrust.scopeName}
                    onChange={(_, val) => setNewTrust({ ...newTrust, scopeName: val || '' })}
                    renderInput={(params) => <TextField {...params} label="Target Scope" placeholder="Select scope..." />}
                  />
                  <Button 
                    variant="contained" 
                    onClick={handleAddTrust}
                    disabled={addingTrust || !newTrust.targetClientId || !newTrust.scopeName}
                  >
                    {addingTrust ? <CircularProgress size={24} /> : "Authorize"}
                  </Button>
                </Stack>
              </Box>
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 3 }}>
          <Button onClick={() => setScopesDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
