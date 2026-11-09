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
const E2E_SAMPLES = '.e2e-samples'

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
      timeout: 120_000,
      command: `node -e "const fs = require('fs'); fs.rmSync('${E2E_DB}', { force: true }); fs.mkdirSync('${E2E_SAMPLES}', { recursive: true }); for (const f of fs.readdirSync('${E2E_SAMPLES}')) fs.rmSync('${E2E_SAMPLES}/' + f, { force: true })" && uvicorn app.main:app --port ${API_PORT}`,
      cwd: 'backend',
      url: `http://127.0.0.1:${API_PORT}/api/health`,
      reuseExistingServer: false,
      env: {
        DATABASE_URL: `sqlite:///./${E2E_DB}`,
        COOKIE_SECURE: 'false',
        RATE_LIMIT_DEFAULT: '100000/minute',
        SAMPLE_STORE: E2E_SAMPLES,
        // Set by CI when the analyzer container runs (see .github/workflows/ci.yml).
        ANALYZER_URL: process.env.E2E_ANALYZER_URL ?? '',
        ANALYZER_TOKEN: process.env.E2E_ANALYZER_TOKEN ?? '',
      },
    },
    {
      // Bind to IPv4 explicitly: on some runners `localhost` resolves to ::1
      // and the health URL below would never answer.
      command: `npx vite preview --host 127.0.0.1 --port ${WEB_PORT} --strictPort`,
      url: `http://127.0.0.1:${WEB_PORT}/`,
      timeout: 120_000,
      reuseExistingServer: false,
      env: { API_PORT: String(API_PORT) },
    },
  ],
})
