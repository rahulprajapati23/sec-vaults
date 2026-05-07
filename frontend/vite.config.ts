import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Proxy all backend API routes through Vite dev server
      // This makes cookies work because both origin + API are on port 5173
      '/auth': { target: 'http://127.0.0.1:8000', changeOrigin: true, secure: false },
      '/files': { target: 'http://127.0.0.1:8000', changeOrigin: true, secure: false },
      '/dam': { target: 'http://127.0.0.1:8000', changeOrigin: true, secure: false },
      '/mfa': { target: 'http://127.0.0.1:8000', changeOrigin: true, secure: false },
      '/analytics': { target: 'http://127.0.0.1:8000', changeOrigin: true, secure: false },
      '/iam': { target: 'http://127.0.0.1:8000', changeOrigin: true, secure: false },
      '/ws': { target: 'ws://127.0.0.1:8000', changeOrigin: true, secure: false, ws: true },
      '/system': { target: 'http://127.0.0.1:8000', changeOrigin: true, secure: false },
      '/reports': { target: 'http://127.0.0.1:8000', changeOrigin: true, secure: false },
    }
  }
})
