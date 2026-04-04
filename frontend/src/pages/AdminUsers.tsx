import { Box, Button, Typography, Paper, Chip, Stack, TextField, Autocomplete, IconButton, Tooltip } from '@mui/material';
import { Table, TableBody, TableCell, TableContainer, TableHead, TableRow } from '@mui/material';
import { CircularProgress, Dialog, DialogTitle, DialogContent, DialogActions, InputAdornment } from '@mui/material';
import { Person as PersonIcon, Phone as PhoneIcon, Edit as EditIcon, Delete as DeleteIcon, Shield as ShieldIcon, LockOpen as LockOpenIcon, Sync as SyncIcon, Info as InfoIcon } from '@mui/icons-material';
import { useState, useEffect } from 'react';
import api from '../api';

interface UserModel {
  id: string;
  email: string;
  mobileNumber?: string;
  roles: string[];
}

interface UserScope {
  id: string;
  clientId: string;
  scope: string;
}

interface ClientModel {
  clientId: string;
  name: string;
}

export default function AdminUsers() {
  const [users, setUsers] = useState<UserModel[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<UserModel | null>(null);
  const [newUser, setNewUser] = useState({ email: '', mobileNumber: '', roles: ['user'] });
  const [submitting, setSubmitting] = useState(false);

  // App-specific scopes state
  const [scopesDialogOpen, setScopesDialogOpen] = useState(false);
  const [manageScopesUser, setManageScopesUser] = useState<UserModel | null>(null);
  const [userScopes, setUserScopes] = useState<UserScope[]>([]);
  const [apps, setApps] = useState<ClientModel[]>([]);
  const [availableOptions, setAvailableOptions] = useState<string[]>([]);
  const [newAppScope, setNewAppScope] = useState({ clientId: '', scope: '' });
  const [addingScope, setAddingScope] = useState(false);

  const fetchUsers = () => {
    setLoading(true);
    api.get('/manage/users')
      .then(res => {
        setUsers(res.data);
        setLoading(false);
      })
      .catch(() => {
        console.error('Error fetching users');
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleOpenCreate = () => {
    setEditingUser(null);
    setNewUser({ email: '', mobileNumber: '', roles: ['user'] });
    setOpen(true);
  };

  const handleOpenEdit = (user: UserModel) => {
    setEditingUser(user);
    setNewUser({ 
      email: user.email, 
      mobileNumber: user.mobileNumber || '', 
      roles: [...user.roles] 
    });
    setOpen(true);
  };

  const handleCreate = async () => {
    setSubmitting(true);
    try {
      if (editingUser) {
        await api.put(`/manage/users/${editingUser.id}`, {
          mobileNumber: newUser.mobileNumber,
          roles: newUser.roles
        });
      } else {
        await api.post('/manage/users', {
          email: newUser.email,
          mobileNumber: newUser.mobileNumber,
          roles: newUser.roles
        });
      }
  
      setOpen(false);
      setNewUser({ email: '', mobileNumber: '', roles: ['user'] });
      fetchUsers();
    } catch (err: unknown) {
      console.error('Failed to save user:', err);
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      alert(`Error: ${errorMessage}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) return;
    try {
      await api.delete(`/manage/users/${id}`);
      fetchUsers();
    } catch (err) {
      console.error('Delete error', err);
    }
  };

  const handleOpenScopes = async (user: UserModel) => {
    setManageScopesUser(user);
    setScopesDialogOpen(true);
    setUserScopes([]);
    setNewAppScope({ clientId: '', scope: '' });
    
    try {
      // Fetch users assigned scopes
      const scopesRes = await api.get(`/manage/users/${user.id}/scopes`);
      setUserScopes(scopesRes.data);
      setAvailableOptions([]);

      // Fetch all apps if not already fetched
      if (apps.length === 0) {
        const appsRes = await api.get('/manage/clients');
        setApps(appsRes.data);
      }
    } catch (err) {
      console.error('Error fetching scope data:', err);
    }
  };

  const handleClientChange = async (clientId: string) => {
    setNewAppScope({ ...newAppScope, clientId, scope: '' });
    setAvailableOptions([]);
    if (clientId) {
      try {
        const [rolesRes, scopesRes] = await Promise.all([
          api.get(`/manage/roles?client_id=${clientId}`),
          api.get(`/manage/scopes?client_id=${clientId}`)
        ]);
        
        const roles = (rolesRes.data as { name: string }[]).map(r => r.name);
        const scopes = (scopesRes.data as { name: string, isClientOnly: boolean }[])
          .filter(s => !s.isClientOnly)
          .map(s => s.name);
        
        // Combine and unique
        const combined = Array.from(new Set([...roles, ...scopes]));
        setAvailableOptions(combined);
      } catch (err) {
        console.error('Error fetching capabilities for client', err);
      }
    }
  };

  const handleAddScope = async () => {
    if (!manageScopesUser || !newAppScope.clientId || !newAppScope.scope) return;
    setAddingScope(true);
    try {
      await api.post(`/manage/users/${manageScopesUser.id}/scopes`, {
        clientId: newAppScope.clientId,
        scope: newAppScope.scope
      });
      setNewAppScope({ ...newAppScope, scope: '' });
      // Refresh
      const res = await api.get(`/manage/users/${manageScopesUser.id}/scopes`);
      setUserScopes(res.data);
    } catch {
      alert('Failed to assign scope');
    } finally {
      setAddingScope(false);
    }
  };

  const handleRemoveScope = async (id: string) => {
    if (!confirm('Remove this scope assignment?')) return;
    try {
      await api.delete(`/manage/users/scopes/${id}`);
      setUserScopes(userScopes.filter(s => s.id !== id));
    } catch (err) {
      alert('Failed to remove scope');
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
        <Typography variant="h4" fontWeight={700} sx={{ letterSpacing: -1 }}>
          User <Box component="span" sx={{ color: 'primary.main' }}>Directory</Box>
        </Typography>
        <Button 
          variant="contained" 
          onClick={handleOpenCreate}
          sx={{ fontFamily: "'JetBrains Mono', monospace" }}
        >
          Provision New User
        </Button>
      </Box>

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle sx={{ fontWeight: 'bold' }}>
          {editingUser ? 'Edit User' : 'Add New User'}
        </DialogTitle>
        <DialogContent sx={{ pt: 2 }}>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label="Email Address"
              fullWidth
              disabled={!!editingUser}
              type="email"
              value={newUser.email}
              onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
              helperText={editingUser ? "Email cannot be changed" : ""}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <PersonIcon fontSize="small" sx={{ opacity: 0.7 }} />
                  </InputAdornment>
                ),
              }}
            />
            <TextField
              label="Mobile Number"
              fullWidth
              value={newUser.mobileNumber}
              onChange={(e) => setNewUser({ ...newUser, mobileNumber: e.target.value })}
              placeholder="+1 234 567 890"
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <PhoneIcon fontSize="small" sx={{ opacity: 0.7 }} />
                  </InputAdornment>
                ),
              }}
            />
            <Autocomplete
              multiple
              options={['user', 'admin', 'operator', 'tester']}
              value={newUser.roles}
              onChange={(_, newValue) => setNewUser({ ...newUser, roles: newValue })}
              renderInput={(params) => (
                <TextField
                  {...params}
                  label="Roles"
                  placeholder="Select roles"
                />
              )}
              renderTags={(value, getTagProps) =>
                value.map((option, index) => (
                  <Chip 
                    label={option} 
                    {...getTagProps({ index })} 
                    size="small" 
                    color={option === 'admin' ? 'secondary' : 'primary'} 
                    variant="filled"
                  />
                ))
              }
            />
          </Stack>
        </DialogContent>
        <DialogActions sx={{ p: 3 }}>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleCreate}
            disabled={submitting || !newUser.email}
          >
            {submitting ? 'Saving...' : editingUser ? 'Update User' : 'Add User'}
          </Button>
        </DialogActions>
      </Dialog>

      {loading ? <CircularProgress /> : (
        <TableContainer component={Paper}>
          <Table sx={{ minWidth: 650 }} aria-label="users table">
            <TableHead>
              <TableRow>
                <TableCell><strong>Email</strong></TableCell>
                <TableCell><strong>Mobile</strong></TableCell>
                <TableCell><strong>User ID</strong></TableCell>
                <TableCell><strong>Roles</strong></TableCell>
                <TableCell align="right"><strong>Actions</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {users.map((row) => (
                <TableRow key={row.id}>
                  <TableCell component="th" scope="row">
                    {row.email}
                  </TableCell>
                  <TableCell>{row.mobileNumber || '-'}</TableCell>
                  <TableCell>{row.id}</TableCell>
                  <TableCell>
                    {row.roles?.map(role => (
                      <Chip key={role} label={role} size="small" sx={{ mr: 0.5 }} color={role === 'admin' ? 'secondary' : 'primary'} variant="filled" />
                    ))}
                  </TableCell>
                  <TableCell align="right">
                    <Stack direction="row" spacing={1} justifyContent="flex-end">
                      <Tooltip title="Manage App Scopes">
                        <IconButton size="small" color="info" onClick={() => handleOpenScopes(row)}>
                          <ShieldIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Edit User">
                        <IconButton size="small" color="primary" onClick={() => handleOpenEdit(row)}>
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete User">
                        <IconButton size="small" color="error" onClick={() => handleDelete(row.id)}>
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </Stack>
                  </TableCell>
                </TableRow>
              ))}
              {users.length === 0 && (
                <TableRow>
                  <TableCell colSpan={3} align="center">No users found.</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* App-Specific Scopes Dialog */}
      <Dialog open={scopesDialogOpen} onClose={() => setScopesDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle sx={{ fontWeight: 'bold' }}>
          App-Specific Scopes: {manageScopesUser?.email}
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Grant specific scopes/roles to this user for specific applications. These will be included in tokens for those apps.
          </Typography>

          <TableContainer component={Paper} variant="outlined" sx={{ mt: 2 }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell><strong>Application</strong></TableCell>
                  <TableCell><strong>Scope / Role</strong></TableCell>
                  <TableCell align="right"><strong>Actions</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {userScopes.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell><Chip label={s.clientId} size="small" icon={<LockOpenIcon sx={{ fontSize: '14px !important' }} />} /></TableCell>
                    <TableCell>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <code>{s.scope}</code>
                        {s.scope.startsWith('api://') && (
                          <Tooltip title="Cross-App Trusted Scope">
                            <SyncIcon color="primary" sx={{ fontSize: 16 }} />
                          </Tooltip>
                        )}
                      </Stack>
                    </TableCell>
                    <TableCell align="right">
                      <IconButton size="small" color="error" onClick={() => handleRemoveScope(s.id)}>
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
                {userScopes.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={3} align="center" sx={{ py: 3 }}>No app-specific scopes assigned.</TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>

          <Box sx={{ mt: 4, pt: 2, borderTop: 1, borderColor: 'divider' }}>
            <Typography variant="subtitle2" gutterBottom fontWeight="bold">Assign New Scope</Typography>
            <Stack direction="row" spacing={2} alignItems="flex-start">
              <Autocomplete
                size="small"
                sx={{ minWidth: 200 }}
                options={apps.map(a => a.clientId)}
                value={newAppScope.clientId}
                onChange={(_, val) => handleClientChange(val || '')}
                renderInput={(params) => <TextField {...params} label="Select Client" />}
              />
              <Autocomplete
                size="small"
                fullWidth
                options={availableOptions}
                value={newAppScope.scope}
                onChange={(_, val) => setNewAppScope({ ...newAppScope, scope: val || '' })}
                renderInput={(params) => (
                  <TextField 
                    {...params} 
                    label="Role / Scope" 
                    placeholder="Select role or scope..."
                    InputProps={{
                      ...params.InputProps,
                      endAdornment: (
                        <>
                          {params.InputProps.endAdornment}
                          <Tooltip title="Qualified scopes (api://client/scope) require Cross-App Trust to be configured for the client.">
                            <InfoIcon color="action" sx={{ fontSize: 18, mr: 1, cursor: 'help' }} />
                          </Tooltip>
                        </>
                      )
                    }}
                  />
                )}
              />
              <Button 
                variant="contained" 
                onClick={handleAddScope}
                disabled={addingScope || !newAppScope.clientId || !newAppScope.scope}
              >
                {addingScope ? <CircularProgress size={24} /> : "Assign"}
              </Button>
            </Stack>
          </Box>
        </DialogContent>
        <DialogActions sx={{ p: 3 }}>
          <Button onClick={() => setScopesDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
