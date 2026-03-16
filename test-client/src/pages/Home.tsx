import { Container, Typography, Button, Box, Paper, Divider } from '@mui/material';
import { useAuth } from '../context/AuthContext';

export default function Home() {
  const { isAuthenticated, login, logout, accessToken, idToken } = useAuth();

  const parseJwt = (token: string) => {
    try {
      return JSON.parse(atob(token.split('.')[1]));
    } catch (e) {
      return null;
    }
  };

  const accessClaims = accessToken ? parseJwt(accessToken) : null;
  const idClaims = idToken ? parseJwt(idToken) : null;

  return (
    <Container maxWidth="md" sx={{ mt: 8 }}>
      <Paper elevation={3} sx={{ p: 4, borderRadius: 2 }}>
        <Typography variant="h3" gutterBottom align="center" sx={{ fontWeight: 'bold', color: 'primary.main' }}>
          OAuth2 Test Client
        </Typography>
        <Typography variant="body1" align="center" color="text.secondary" paragraph>
          This application tests the Authorization Code flow with PKCE against the <strong>ar-auth</strong> identity provider.
        </Typography>

        <Divider sx={{ my: 4 }} />

        {!isAuthenticated ? (
          <Box sx={{ textAlign: 'center', py: 4 }}>
            <Button variant="contained" size="large" onClick={login} sx={{ px: 6, py: 1.5, fontSize: '1.1rem' }}>
              Login with ar-auth
            </Button>
          </Box>
        ) : (
          <Box>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
              <Typography variant="h5">Welcome, {accessClaims?.email || 'User'}</Typography>
              <Button variant="outlined" color="error" onClick={logout}>
                Logout
              </Button>
            </Box>

            <Typography variant="h6" gutterBottom color="primary">Access Token Claims</Typography>
            <Paper variant="outlined" sx={{ p: 2, bgcolor: 'grey.50', mb: 3, overflowX: 'auto' }}>
              <pre>{JSON.stringify(accessClaims, null, 2)}</pre>
            </Paper>

            {idToken && (
              <>
                <Typography variant="h6" gutterBottom color="primary">ID Token Claims</Typography>
                <Paper variant="outlined" sx={{ p: 2, bgcolor: 'grey.50', mb: 3, overflowX: 'auto' }}>
                  <pre>{JSON.stringify(idClaims, null, 2)}</pre>
                </Paper>
              </>
            )}

            <Typography variant="h6" gutterBottom color="secondary">Raw Access Token</Typography>
            <Typography variant="body2" sx={{ wordBreak: 'break-all', fontFamily: 'monospace', p: 1, bgcolor: 'grey.100' }}>
              {accessToken}
            </Typography>
          </Box>
        )}
      </Paper>
    </Container>
  );
}
