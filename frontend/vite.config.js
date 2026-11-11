import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { PAGE_HEADERS } from './security-headers.js'

// Vite configuration for Nik.
// - React plugin (JSX + fast refresh)
// - Tailwind CSS v4 plugin (no tailwind.config.js needed)

// In development and in `vite preview` the frontend calls the API at /api.
// Proxy those requests to the local FastAPI backend so `npm run dev` and the
// end-to-end tests work without nginx, which performs this reverse-proxy in
// production (see README § Deployment). API_PORT lets the E2E run use a port
// that does not clash with a dev backend.
const apiProxy = {
  '/api': {
    target: `http://127.0.0.1:${process.env.API_PORT ?? 8000}`,
    changeOrigin: true,
  },
}

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { proxy: apiProxy },
  // The production headers (Content-Security-Policy included), so the end-to-end
  // tests run under the policy nginx sends.
  preview: { proxy: apiProxy, headers: PAGE_HEADERS },
  build: {
    // sql.js (WASM) is lazy-loaded: raise the warning limit for the chunks
    // produced by the tabs' code-splitting.
    chunkSizeWarningLimit: 1500,
  },
})
