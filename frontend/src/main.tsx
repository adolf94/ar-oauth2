import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { RouterProvider } from '@tanstack/react-router'
import { router } from './router'
import { ThemeControlProvider } from './components/ThemeContext'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeControlProvider>
      <RouterProvider router={router} />
    </ThemeControlProvider>
  </StrictMode>,
)
