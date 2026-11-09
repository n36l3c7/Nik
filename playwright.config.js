import { defineConfig, devices } from '@playwright/test'

/*
 * End-to-end smoke tests (`npm run test:e2e`).
 *
 * Playwright starts the real stack: the FastAPI backend on a throw-away SQLite
 * database (deleted before every run, so the first-run screen always shows)
 * and the production build served by `vite preview`, which proxies /api to
 * that backend. Run `npm run build` first; CI does. The backend needs the
 * Python dependencies from backend/requirements-dev.txt on PATH (a venv is
 * fine: activate it before running the tests).
 */

const API_PORT = 8765
const WEB_PORT = 4173
const E2E_DB = '.e2e.db'

export default defineConfig({
  testDir: 'e2e',
  timeout: 60_000,
  // The smoke flow is one story (first run → sign in → incident → data), so
  // the specs run in order on a single worker.
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: `http://127.0.0.1:${WEB_PORT}`,
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: [
    {
      command: `node -e "require('fs').rmSync('${E2E_DB}', { force: true })" && uvicorn app.main:app --port ${API_PORT}`,
      cwd: 'backend',
      url: `http://127.0.0.1:${API_PORT}/api/health`,
      reuseExistingServer: false,
      env: {
        DATABASE_URL: `sqlite:///./${E2E_DB}`,
        COOKIE_SECURE: 'false',
        RATE_LIMIT_DEFAULT: '100000/minute',
      },
    },
    {
      command: `npx vite preview --port ${WEB_PORT} --strictPort`,
      url: `http://127.0.0.1:${WEB_PORT}/`,
      reuseExistingServer: false,
      env: { API_PORT: String(API_PORT) },
    },
  ],
})
