import { Box, Button, Typography, Paper, Chip, Stack, TextField, Autocomplete, IconButton, Tooltip } from '@mui/material';
import { Table, TableBody, TableCell, TableContainer, TableHead, TableRow } from '@mui/material';
import { CircularProgress, Dialog, DialogTitle, DialogContent, DialogActions, InputAdornment } from '@mui/material';
import { Person as PersonIcon, Phone as PhoneIcon, Edit as EditIcon, Delete as DeleteIcon } from '@mui/icons-material';
import { useState, useEffect } from 'react';
import api from '../api';

interface UserModel {
  id: string;
  email: string;
  mobileNumber?: string;
  roles: string[];
}

export default function AdminUsers() {
  const [users, setUsers] = useState<UserModel[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<UserModel | null>(null);
  const [newUser, setNewUser] = useState({ email: '', mobileNumber: '', roles: ['user'] });
  const [submitting, setSubmitting] = useState(false);

  const fetchUsers = () => {
    setLoading(true);
    api.get('/manage/users')
      .then(res => {
        setUsers(res.data);
        setLoading(false);
      })
      .catch(err => {
        console.error('Error fetching users:', err);
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
    } catch (err: any) {
      console.error('Failed to save user:', err);
      alert(`Error: ${err.response?.data || err.message}`);
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
    </Box>
  );
}
