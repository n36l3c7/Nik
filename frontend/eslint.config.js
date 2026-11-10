/*
 * ESLint (flat config). `npm run lint` checks the frontend; CI runs it too.
 *  - @eslint/js recommended rules
 *  - JSX: ESLint 10's scope analysis counts a component used only in JSX as
 *    used, so eslint-plugin-react (react/jsx-uses-vars) is no longer needed
 *  - eslint-plugin-react-hooks: the classic Rules of Hooks and exhaustive deps
 */
import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'

export default [
  { ignores: ['dist/', 'node_modules/'] },
  js.configs.recommended,
  {
    files: ['**/*.{js,jsx}'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: { ...globals.browser },
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'error',
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },
  {
    // Node-side files: tests, build config, fixture scripts.
    files: ['**/*.test.js', 'e2e/**/*.js', 'vite.config.js', 'eslint.config.js', 'playwright*.config.js'],
    languageOptions: { globals: { ...globals.node } },
  },
]
