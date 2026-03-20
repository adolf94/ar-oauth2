import { useEffect, useState, useRef } from 'react';
import { useSearch } from '@tanstack/react-router';
import { Box, CircularProgress, Typography, Container, Card, CardContent } from '@mui/material';
import { CheckCircleOutline as SuccessIcon, ErrorOutline as ErrorIcon, Android as AndroidIcon } from '@mui/icons-material';
import api from '../api';

export default function AutomateCallback() {
  const searchParams = useSearch({ strict: false }) as { code?: string, state?: string };
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const processed = useRef(false);

  useEffect(() => {
    if (processed.current) return;

    const { code, state } = searchParams;

    if (!code) {
      setStatus('error');
      setErrorMessage('No authorization code found in URL.');
      return;
    }

    processed.current = true;

    const triggerPush = async () => {
      try {
        await api.post('/automate/push', { code, state });
        setStatus('success');
      } catch (err: any) {
        console.error('Automate push error:', err);
        setStatus('error');
        setErrorMessage(err.response?.data?.error_description || 'Failed to trigger device push.');
      }
    };

    triggerPush();
  }, [searchParams]);

  return (
    <Container maxWidth="sm" sx={{ py: 12 }}>
      <Card sx={{ 
        borderRadius: 6, 
        textAlign: 'center', 
        p: 4,
        background: 'rgba(255, 255, 255, 0.02)',
        backdropFilter: 'blur(20px)',
        border: '1px solid rgba(255, 255, 255, 0.1)',
        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)'
      }}>
        <CardContent>
          {status === 'loading' && (
            <Box>
              <CircularProgress size={60} sx={{ mb: 4, color: 'primary.main' }} />
              <Typography variant="h5" fontWeight={700} gutterBottom>
                Authenticating...
              </Typography>
              <Typography color="text.secondary">
                Verifying your credentials and preparing the secure push to your device.
              </Typography>
            </Box>
          )}

          {status === 'success' && (
            <Box>
              <SuccessIcon sx={{ fontSize: 80, color: 'success.main', mb: 3 }} />
              <Typography variant="h4" fontWeight={800} gutterBottom sx={{ letterSpacing: -1 }}>
                Authorized
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1, mb: 3, opacity: 0.8 }}>
                <AndroidIcon fontSize="small" color="success" />
                <Typography variant="body2" fontWeight={600} color="success.main">
                  Push sent to your Android device
                </Typography>
              </Box>
              <Typography color="text.secondary" sx={{ mb: 4 }}>
                Your authorization code has been securely transmitted. You can now close this tab.
              </Typography>
            </Box>
          )}

          {status === 'error' && (
            <Box>
              <ErrorIcon sx={{ fontSize: 80, color: 'error.main', mb: 3 }} />
              <Typography variant="h5" fontWeight={700} color="error.main" gutterBottom>
                Authorization Failed
              </Typography>
              <Typography color="text.secondary" sx={{ mb: 4 }}>
                {errorMessage || 'An unexpected error occurred during the callback process.'}
              </Typography>
            </Box>
          )}
        </CardContent>
      </Card>
      
      <Typography variant="caption" sx={{ display: 'block', mt: 4, textAlign: 'center', opacity: 0.5, letterSpacing: 1, textTransform: 'uppercase' }}>
        AR Auth • Llamalabs Automate Integration
      </Typography>
    </Container>
  );
}
