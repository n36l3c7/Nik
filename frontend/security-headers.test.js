import assert from 'node:assert/strict'
import { test } from 'node:test'
import { CONTENT_SECURITY_POLICY, PAGE_HEADERS, nginxIncludes } from './security-headers.js'

test('the policy lets only the app run scripts and talk to its own origin', () => {
  const directives = Object.fromEntries(
    CONTENT_SECURITY_POLICY.split('; ').map((part) => [part.split(' ')[0], part.split(' ').slice(1)]),
  )
  assert.deepEqual(directives['script-src'], ["'self'", "'wasm-unsafe-eval'"])
  assert.deepEqual(directives['connect-src'], ["'self'"])
  assert.deepEqual(directives['object-src'], ["'none'"])
  assert.deepEqual(directives['base-uri'], ["'none'"])
  assert.deepEqual(directives['frame-ancestors'], ["'none'"])
  for (const [name, sources] of Object.entries(directives)) {
    if (name !== 'style-src') assert.ok(!sources.includes("'unsafe-inline'"), name)
    assert.ok(!sources.includes("'unsafe-eval'"), name)
    assert.ok(!sources.includes('*'), name)
  }
})

test('the nginx includes are valid add_header lines for pages and for the API', () => {
  const files = nginxIncludes()
  assert.deepEqual(Object.keys(files).sort(), ['nik-headers-api.conf', 'nik-headers-page.conf'])
  for (const content of Object.values(files)) {
    for (const line of content.trim().split('\n')) {
      // One header per line, the value in double quotes with none inside.
      assert.match(line, /^add_header [A-Za-z-]+ "[^"]+" always;$/)
    }
    assert.match(content, /Strict-Transport-Security/)
    assert.match(content, /X-Content-Type-Options "nosniff"/)
  }
  assert.match(files['nik-headers-page.conf'], /Content-Security-Policy/)
  // The API serves its own documents (Swagger UI, PDF): no app policy there.
  assert.doesNotMatch(files['nik-headers-api.conf'], /Content-Security-Policy/)
  assert.equal(PAGE_HEADERS['X-Frame-Options'], 'DENY')
})
