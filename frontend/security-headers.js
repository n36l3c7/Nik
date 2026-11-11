/*
 * The security headers sent with the app's pages: one definition, used by
 * `vite preview` (so the end-to-end tests run under the same policy as
 * production) and written into the nginx configuration when the image is
 * built (`node security-headers.js`, see the Dockerfile).
 *
 * Nik shows attacker-controlled content all day: file names, URLs, e-mail
 * bodies, strings from malware. React escapes it and hostile HTML only ever
 * goes into sandboxed frames, and this policy is the second line of defence
 * should either fail: nothing but the app's own scripts can run, the app
 * talks to its own origin only, and it cannot be framed by another site.
 *
 *  - script-src: the bundle, plus WebAssembly for sql.js (browser databases
 *    are read in the browser).
 *  - style-src 'unsafe-inline': style attributes, and the sandboxed frames
 *    (they inherit this policy) render e-mails and reports with inline styles.
 *  - img-src http(s): the e-mail frame inherits this policy too, and "Load
 *    images" lets the analyst fetch a message's remote images on purpose.
 */

export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: https: http:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "worker-src 'self' blob:",
  "frame-src 'self' blob:",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ')

/** Sent with every response of the web container (the API's included). */
export const COMMON_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
}

/** Sent with the app's own pages and assets. */
export const PAGE_HEADERS = {
  ...COMMON_HEADERS,
  'Content-Security-Policy': CONTENT_SECURITY_POLICY,
  'X-Frame-Options': 'DENY',
}

const nginxLines = (headers) =>
  Object.entries(headers)
    .map(([name, value]) => `add_header ${name} "${value}" always;`)
    .join('\n')

/** The nginx include files generated at image build: `{ fileName: content }`. */
export function nginxIncludes() {
  // Browsers ignore HSTS on plain HTTP and on a certificate they do not trust,
  // so it is safe to send always; with a trusted certificate it pins HTTPS.
  const hsts = 'add_header Strict-Transport-Security "max-age=31536000" always;'
  return {
    'nik-headers-page.conf': `${nginxLines(PAGE_HEADERS)}\n${hsts}\n`,
    // The API also serves documents of its own (Swagger UI from /api/docs, PDF
    // reports): they get the generic protections, not the app's policy.
    'nik-headers-api.conf': `${nginxLines({ ...COMMON_HEADERS, 'X-Frame-Options': 'SAMEORIGIN' })}\n${hsts}\n`,
  }
}

// `node security-headers.js <directory>` writes the include files there.
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop())) {
  const { mkdirSync, writeFileSync } = await import('node:fs')
  const directory = process.argv[2] ?? '.'
  mkdirSync(directory, { recursive: true })
  for (const [name, content] of Object.entries(nginxIncludes())) writeFileSync(`${directory}/${name}`, content)
}
