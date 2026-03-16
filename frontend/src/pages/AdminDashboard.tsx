import { Typography, Card, CardContent, Grid, Box } from '@mui/material';

export default function AdminDashboard() {
  return (
    <Box>
      <Typography variant="h4" fontWeight={700} gutterBottom sx={{ letterSpacing: -1 }}>
        System <Box component="span" sx={{ color: 'primary.main' }}>Overview</Box>
      </Typography>
      <Grid container spacing={3} sx={{ mt: 2 }}>
        <Grid size={{ xs: 12, sm: 6, md: 4 }}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.8rem', fontWeight: 700 }}>
                TOTAL_USERS
              </Typography>
              <Typography variant="h3" fontWeight={700}>
                12
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 4 }}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.8rem', fontWeight: 700 }}>
                REGISTERED_APPS
              </Typography>
              <Typography variant="h3" fontWeight={700}>
                3
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}
