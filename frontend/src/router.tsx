import { createRootRoute, createRoute, createRouter, Navigate, lazyRouteComponent } from '@tanstack/react-router';
import AuthGuard from './components/AuthGuard';

const Login = lazyRouteComponent(() => import('./pages/Login'));
const AdminLayout = lazyRouteComponent(() => import('./layouts/AdminLayout'));
const AdminDashboard = lazyRouteComponent(() => import('./pages/AdminDashboard'));
const AdminApps = lazyRouteComponent(() => import('./pages/AdminApps'));
const AdminUsers = lazyRouteComponent(() => import('./pages/AdminUsers'));
const Profile = lazyRouteComponent(() => import('./pages/Profile'));
const AuthCallback = lazyRouteComponent(() => import('./pages/AuthCallback'));
const PopupCallback = lazyRouteComponent(() => import('./pages/PopupCallback'));
const ErrorPage = lazyRouteComponent(() => import('./pages/ErrorPage'));
const AutomateCallback = lazyRouteComponent(() => import('./pages/AutomateCallback'));

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

const automateCallbackRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/profile/automate/callback',
  component: AutomateCallback,
});

const errorPageRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/error',
  component: ErrorPage,
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
  automateCallbackRoute,
  adminRoute,
  errorPageRoute
]);

export const router = createRouter({ routeTree });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
