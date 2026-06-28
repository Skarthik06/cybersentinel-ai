import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    port: 3000,
    proxy: {
      // Proxies /api calls to the CyberSentinel FastAPI backend
      '/api': { target: 'http://api-gateway:8080', changeOrigin: true },
      '/auth': { target: 'http://api-gateway:8080', changeOrigin: true },
    }
  }
})
