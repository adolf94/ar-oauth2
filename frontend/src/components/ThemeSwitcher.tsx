import { IconButton } from '@mui/material';
import { DarkMode, LightMode } from '@mui/icons-material';
import { useThemeControl } from './ThemeContext';

export default function ThemeSwitcher() {
  const { mode, toggleTheme } = useThemeControl();

  return (
    <IconButton onClick={toggleTheme} color="inherit" sx={{ transition: 'transform 0.2s' }}>
      {mode === 'dark' ? <LightMode fontSize="small" /> : <DarkMode fontSize="small" />}
    </IconButton>
  );
}
