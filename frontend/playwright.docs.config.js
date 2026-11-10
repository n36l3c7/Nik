import base from './playwright.config.js'

/*
 * Screenshots of the user guide (`npm run docs:screenshots`): the same stack as
 * the end-to-end test, the spec in e2e/docs/, PNGs written to docs/img/.
 */
export default {
  ...base,
  testDir: 'e2e/docs',
  testIgnore: [],
  timeout: 180_000,
  reporter: 'list',
}
