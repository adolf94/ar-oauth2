import { Box, Typography, Container, Button, Paper } from '@mui/material';
import { ErrorOutline as ErrorIcon } from '@mui/icons-material';
import { useSearch, Link } from '@tanstack/react-router';
import ThemeSwitcher from '../components/ThemeSwitcher';

interface ErrorSearchParams {
  error?: string;
  error_description?: string;
}

export default function ErrorPage() {
  const searchParams = useSearch({ strict: false }) as ErrorSearchParams;
  const errorCode = searchParams.error || 'unknown_error';
  const errorDescription = searchParams.error_description || 'An unexpected error occurred during the authorization process.';

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

      <Container maxWidth="sm">
        <Paper 
          elevation={0}
          sx={{ 
            p: { xs: 4, md: 6 }, 
            textAlign: 'center',
            borderRadius: 4,
            border: '1px solid',
            borderColor: 'divider',
            backgroundColor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.02)' : 'rgba(0,0,0,0.01)',
            backdropFilter: 'blur(10px)'
          }}
        >
          <ErrorIcon color="error" sx={{ fontSize: 64, mb: 2, opacity: 0.8 }} />
          
          <Typography variant="h4" fontWeight={700} gutterBottom sx={{ letterSpacing: -1 }}>
            Something went wrong
          </Typography>
          
          <Typography 
            variant="body1" 
            color="text.secondary" 
            sx={{ 
              mb: 4, 
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '0.9rem',
              backgroundColor: (theme) => theme.palette.mode === 'dark' ? 'rgba(0,0,0,0.2)' : 'rgba(0,0,0,0.05)',
              p: 2,
              borderRadius: 2,
              border: '1px solid',
              borderColor: 'divider'
            }}
          >
            <Box component="span" sx={{ color: 'error.main', fontWeight: 700 }}>
              {errorCode.toUpperCase().replace(/_/g, ' ')}
            </Box>
            <Box component="div" sx={{ mt: 1, opacity: 0.8 }}>
              {errorDescription}
            </Box>
          </Typography>

          <Button 
            component={Link} 
            to="/login"
            variant="contained" 
            disableElevation
            sx={{ px: 4, py: 1.5, borderRadius: 2, fontWeight: 700 }}
          >
            Return to Login
          </Button>
        </Paper>

        <Typography variant="caption" sx={{ display: 'block', mt: 4, textAlign: 'center', color: 'text.disabled', fontFamily: "'JetBrains Mono', monospace" }}>
          PRAGMATIC ARCHITECT SYSTEM v1.0
        </Typography>
      </Container>
    </Box>
  );
}
