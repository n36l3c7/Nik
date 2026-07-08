import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Vite configuration for CSAP.
// - React plugin (JSX + fast refresh)
// - Tailwind CSS v4 plugin (no tailwind.config.js needed)
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // In development the frontend calls the API at /api. Proxy those requests to
    // the local FastAPI backend so `npm run dev` works end-to-end. In production
    // nginx performs this reverse-proxy instead (see README § Deployment).
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
  build: {
    // sql.js (WASM) is lazy-loaded: raise the warning limit for the chunks
    // produced by the tabs' code-splitting.
    chunkSizeWarningLimit: 1500,
  },
})
