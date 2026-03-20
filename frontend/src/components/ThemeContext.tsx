import { createContext, useContext, useState, useMemo, useEffect, type ReactNode } from 'react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';

type ThemeMode = 'light' | 'dark';

interface ThemeContextType {
  mode: ThemeMode;
  toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export const useThemeControl = () => {
  const context = useContext(ThemeContext);
  if (!context) throw new Error('useThemeControl must be used within a ThemeControlProvider');
  return context;
};

export const ThemeControlProvider = ({ children }: { children: ReactNode }) => {
  const [mode, setMode] = useState<ThemeMode>(() => {
    if (typeof window === 'undefined') return 'light';

    // 1. Check Query Params (highest priority)
    const params = new URLSearchParams(window.location.search);
    const themeParam = params.get('theme');
    if (themeParam === 'light' || themeParam === 'dark') {
        // Store in sessionStorage to persist in that session
        sessionStorage.setItem('theme-session', themeParam);
        return themeParam as ThemeMode;
    }

    // 2. Check SessionStorage (previously set from query param)
    const sessionSaved = sessionStorage.getItem('theme-session');
    if (sessionSaved === 'light' || sessionSaved === 'dark') {
        return sessionSaved as ThemeMode;
    }

    // 3. Check LocalStorage (persistent preference from manual toggle)
    const saved = localStorage.getItem('theme-mode');
    if (saved === 'light' || saved === 'dark') {
        return saved as ThemeMode;
    }

    // 4. Check Browser Current Setting (fallback)
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      return 'dark';
    }

    return 'light'; // Final fallback to light mode
  });

  useEffect(() => {
    // Listen for system preference changes if no manual override or session storage exists
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleSystemThemeChange = (e: MediaQueryListEvent) => {
      if (!localStorage.getItem('theme-mode') && !sessionStorage.getItem('theme-session')) {
        setMode(e.matches ? 'dark' : 'light');
      }
    };

    mediaQuery.addEventListener('change', handleSystemThemeChange);
    return () => mediaQuery.removeEventListener('change', handleSystemThemeChange);
  }, []);

  const toggleTheme = () => {
    setMode((prev) => {
      const next = prev === 'light' ? 'dark' : 'light';
      // Manual toggle persists in localStorage
      localStorage.setItem('theme-mode', next);
      // Clear session storage so manual toggle takes priority over old query param
      sessionStorage.removeItem('theme-session');
      return next;
    });
  };

  const theme = useMemo(() => createTheme({
    palette: {
      mode,
      primary: {
        main: mode === 'dark' ? '#BB86FC' : '#8E00E5', // Light Purple (Dark Theme) / Deep Purple (Light Theme)
      },
      secondary: {
        main: mode === 'dark' ? '#00F5FF' : '#007B83', // Terminal Cyan / Deep Teal
      },
      background: {
        default: mode === 'dark' ? '#0F0F0F' : '#FDFDFB', // Carbon Black / Soft White
        paper: mode === 'dark' ? '#1E1E20' : '#FFFFFF', // Warm Slate / Pure White
      },
      text: {
        primary: mode === 'dark' ? '#F4F1DE' : '#1A1A1A', // Oat Milk / Dark Slate
      },
      divider: mode === 'dark' ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.08)',
    },
    typography: {
      fontFamily: "'Inter', sans-serif",
      h1: { fontWeight: 700, letterSpacing: '-0.02em' },
      h2: { fontWeight: 700, letterSpacing: '-0.02em' },
      h3: { fontWeight: 700, letterSpacing: '-0.02em' },
      h4: { fontWeight: 700, letterSpacing: '-0.01em' },
      h5: { fontWeight: 700, letterSpacing: '-0.01em' },
      h6: { fontWeight: 700, letterSpacing: '-0.01em' },
      button: {
        textTransform: 'none',
        fontWeight: 600,
      },
    },
    shape: {
      borderRadius: 6,
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            scrollbarColor: mode === 'dark' ? "#2d2d30 #0f0f0f" : "#e0e0e0 #fdfdfb",
            "&::-webkit-scrollbar": {
              width: 8,
              height: 8,
            },
            "&::-webkit-scrollbar-track": {
              backgroundColor: mode === 'dark' ? "#0f0f0f" : "#fdfdfb",
            },
            "&::-webkit-scrollbar-thumb": {
              backgroundColor: mode === 'dark' ? "#2d2d30" : "#e0e0e0",
              borderRadius: 8,
            },
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: {
            borderRadius: 6,
            transition: 'all 200ms cubic-bezier(0.4, 0, 0.2, 1)',
            '&:hover': {
              transform: 'translateY(-1px)',
              boxShadow: mode === 'dark' 
                ? '0 4px 12px rgba(161, 0, 255, 0.2)' 
                : '0 4px 12px rgba(142, 0, 229, 0.15)',
            },
            '&:active': {
              transform: 'translateY(0)',
            },
          },
          contained: {
            boxShadow: 'none',
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            backgroundImage: 'none',
            backgroundColor: mode === 'dark' ? '#1E1E20' : '#FFFFFF',
            border: `1px solid ${mode === 'dark' ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.05)'}`,
            boxShadow: mode === 'dark' 
              ? '0 4px 20px rgba(0,0,0,0.4)' 
              : '0 4px 20px rgba(0,0,0,0.03)',
            transition: 'all 250ms ease-in-out',
            '&:hover': {
              borderColor: mode === 'dark' ? 'rgba(161, 0, 255, 0.4)' : 'rgba(142, 0, 229, 0.3)',
              transform: 'translateY(-2px)',
            },
          },
        },
      },
      MuiListItemButton: {
          styleOverrides: {
              root: {
                  borderRadius: 6,
                  margin: '4px 8px',
                  '&.Mui-selected': {
                      borderLeft: `4px solid ${mode === 'dark' ? '#A100FF' : '#8E00E5'}`,
                      backgroundColor: mode === 'dark' ? 'rgba(161, 0, 255, 0.12)' : 'rgba(161, 0, 255, 0.08)',
                      '&:hover': {
                          backgroundColor: mode === 'dark' ? 'rgba(161, 0, 255, 0.18)' : 'rgba(161, 0, 255, 0.12)',
                      }
                  }
              }
          }
      }
    },
  }), [mode]);

  return (
    <ThemeContext.Provider value={{ mode, toggleTheme }}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        {children}
      </ThemeProvider>
    </ThemeContext.Provider>
  );
};
