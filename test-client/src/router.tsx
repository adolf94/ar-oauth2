import { createRootRoute, createRoute, createRouter, Outlet } from '@tanstack/react-router';
import Home from './pages/Home';
import Callback from './pages/Callback';
import { AuthProvider } from './context/AuthContext';

const rootRoute = createRootRoute({
  component: () => (
    <AuthProvider>
      <Outlet />
    </AuthProvider>
  ),
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: Home,
});

const callbackRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/callback',
  component: Callback,
});

const routeTree = rootRoute.addChildren([indexRoute, callbackRoute]);

export const router = createRouter({ routeTree });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
