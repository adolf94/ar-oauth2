import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import mkcert from 'vite-plugin-mkcert'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), mkcert()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:7112',
        changeOrigin: true,
        secure: false
      },
      '/.well-known': {
        target: 'http://localhost:7112',
        changeOrigin: true,
        secure: false
      }
    }
  }
})
