import { createRootRoute, createRoute, createRouter, Navigate } from '@tanstack/react-router';
import Login from './pages/Login';
import AdminLayout from './layouts/AdminLayout';
import AdminDashboard from './pages/AdminDashboard';
import AdminApps from './pages/AdminApps';
import AdminUsers from './pages/AdminUsers';
import Profile from './pages/Profile';
import AuthCallback from './pages/AuthCallback';
import PopupCallback from './pages/PopupCallback';
import AuthGuard from './components/AuthGuard';

const rootRoute = createRootRoute();

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: () => <Navigate to="/profile" />,
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  component: Login,
});

const authCallbackRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/auth/callback',
  component: AuthCallback,
});

const popupCallbackRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/auth/popup-callback',
  component: PopupCallback,
});

const profileRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/profile',
  component: () => (
    <AuthGuard>
      <Profile />
    </AuthGuard>
  ),
});

const adminRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/admin',
  component: () => (
    <AuthGuard requiredRole="admin">
      <AdminLayout />
    </AuthGuard>
  ),
});

const adminIndexRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: '/',
  component: AdminDashboard,
});

const adminAppsRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: '/apps',
  component: AdminApps,
});

const adminUsersRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: '/users',
  component: AdminUsers,
});

adminRoute.addChildren([adminIndexRoute, adminAppsRoute, adminUsersRoute]);

const routeTree = rootRoute.addChildren([
  indexRoute, 
  loginRoute, 
  authCallbackRoute, 
  popupCallbackRoute,
  profileRoute, 
  adminRoute
]);

export const router = createRouter({ routeTree });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
