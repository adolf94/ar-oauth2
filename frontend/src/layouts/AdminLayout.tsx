import { Box, Drawer, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Typography, AppBar, Toolbar, Button } from '@mui/material';
import DashboardIcon from '@mui/icons-material/Dashboard';
import AppsIcon from '@mui/icons-material/Apps';
import PeopleIcon from '@mui/icons-material/People';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import { Outlet, useNavigate, useLocation } from '@tanstack/react-router';
import ThemeSwitcher from '../components/ThemeSwitcher';

const drawerWidth = 240;

export default function AdminLayout() {
  const navigate = useNavigate();
  const location = useLocation();

  const navItems = [
    { text: 'Dashboard', icon: <DashboardIcon />, path: '/admin' },
    { text: 'Applications', icon: <AppsIcon />, path: '/admin/apps' },
    { text: 'Users', icon: <PeopleIcon />, path: '/admin/users' },
  ];

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh', bgcolor: 'background.default' }}>
      <AppBar position="fixed" sx={{ zIndex: (theme) => theme.zIndex.drawer + 1, bgcolor: 'background.paper', color: 'text.primary', boxShadow: 'none', borderBottom: '1px solid', borderColor: 'divider' }}>
        <Toolbar sx={{ justifyContent: 'space-between' }}>
          <Typography variant="h6" noWrap component="div" sx={{ fontWeight: 800, letterSpacing: -1, textTransform: 'uppercase' }}>
            <Box component="span" sx={{ color: 'primary.main', fontSize: '1.2em' }}>A</Box><Box component="span" sx={{ color: 'primary.main', fontSize: '1.2em' }}>R</Box> <Box component="span" sx={{ fontSize: '0.6em', opacity: 0.6, fontWeight: 400, ml: 1 }}>ATLAS RUNTIME</Box>
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Button
              size="small"
              startIcon={<AccountCircleIcon />}
              onClick={() => navigate({ to: '/profile' })}
              sx={{ mr: 1, fontFamily: "'JetBrains Mono', monospace", fontSize: '0.8rem' }}
            >
              My Profile
            </Button>
            <ThemeSwitcher />
          </ Box>
        </Toolbar>
      </AppBar>
      <Drawer
        variant="permanent"
        sx={{
          width: drawerWidth,
          flexShrink: 0,
          [`& .MuiDrawer-paper`]: {
            width: drawerWidth,
            boxSizing: 'border-box',
            bgcolor: 'background.default',
            borderRight: '1px solid',
            borderColor: 'divider'
          },
        }}
      >
        <Toolbar />
        <Box sx={{ overflow: 'auto', mt: 2 }}>
          <List>
            {navItems.map((item) => (
              <ListItem key={item.text} disablePadding>
                <ListItemButton
                  selected={location.pathname === item.path || (item.path !== '/admin' && location.pathname.startsWith(item.path))}
                  onClick={() => navigate({ to: item.path })}
                  sx={{ py: 1.5 }}
                >
                  <ListItemIcon sx={{ color: location.pathname.startsWith(item.path) ? 'primary.main' : 'inherit' }}>
                    {item.icon}
                  </ListItemIcon>
                  <ListItemText
                    primary={item.text}
                    primaryTypographyProps={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: '0.9rem',
                      fontWeight: location.pathname.startsWith(item.path) ? 700 : 400
                    }}
                  />
                </ListItemButton>
              </ListItem>
            ))}
          </List>
        </Box>
      </Drawer>
      <Box component="main" sx={{ flexGrow: 1, p: 4 }}>
        <Toolbar />
        <Outlet />
      </Box>
    </Box>
  );
}
