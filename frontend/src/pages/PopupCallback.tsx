import { useEffect, useRef } from 'react';
import { UserManager } from 'oidc-client-ts';
import { Box, CircularProgress, Typography } from '@mui/material';

export default function PopupCallback() {
  const processed = useRef(false);

  useEffect(() => {
    if (processed.current) return;
    processed.current = true;
    // We don't need full config here just to finish the callback, 
    // but the library needs to know we are in query mode
    const userManager = new UserManager({
        authority: window.location.origin + "/api",
        client_id: "ar-auth-system", // This is ignored during callback completion
        redirect_uri: window.location.href,
        response_mode: "query"
    });

    userManager.signinPopupCallback()
      .then(() => {
        console.log("Popup login completed via oidc-client-ts");
        // The library handles closing the window automatically if it works
      })
      .catch((err) => {
        console.error("Popup callback error:", err);
        // Fallback: If it's not a standard OIDC request, try manual close
        if (window.opener) {
            setTimeout(() => window.close(), 1000);
        }
      });
  }, []);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100vh', bgcolor: '#121212', color: 'white' }}>
      <CircularProgress color="inherit" />
      <Typography sx={{ mt: 2 }}>Authenticating...</Typography>
    </Box>
  );
}
