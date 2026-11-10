import test from 'node:test'
import assert from 'node:assert/strict'
import {
  authResult,
  formatDelay,
  frameCsp,
  frameDocument,
  hexRows,
  mailEvents,
  previewKind,
  toPagePoint,
  resultColor,
  verdictMeta,
} from './mail.js'

test('verdicts and authentication colours', () => {
  assert.equal(verdictMeta('phishing').color, 'red')
  assert.equal(verdictMeta('unknown').label, 'no strong signs')
  assert.equal(resultColor('pass'), 'emerald')
  assert.equal(resultColor('softfail'), 'red')
  assert.equal(resultColor('temperror'), 'amber')
  assert.equal(resultColor('none'), 'slate')
})

test("authResult prefers Nik's check, then a trusted server", () => {
  const auth = {
    verified: { spf: { result: 'fail', detail: 'x' }, dkim: { result: 'temperror', detail: 'dns' } },
    reported: {
      summary: { dkim: { result: 'pass', detail: 'd', trusted: true }, dmarc: { result: 'fail', trusted: false } },
    },
  }
  assert.deepEqual(authResult(auth, 'spf'), { result: 'fail', source: 'nik', detail: 'x' })
  assert.equal(authResult(auth, 'dkim').source, 'server')
  assert.equal(authResult(auth, 'dmarc').source, 'header')
  assert.equal(authResult({}, 'arc').result, 'none')
})

test('the frame refuses every request unless images are loaded', () => {
  assert.match(frameCsp(false), /default-src 'none'; img-src data:;/)
  assert.match(frameCsp(true), /img-src data: https: http:/)
  assert.doesNotMatch(frameCsp(true), /script-src/)
  const doc = frameDocument('<p>hi</p>')
  assert.match(doc, /Content-Security-Policy" content="default-src 'none'/)
  assert.match(doc, /<body><p>hi<\/p><\/body>/)
})

test('hex rows and delays', () => {
  const rows = hexRows(new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x41]), 32, 4)
  assert.deepEqual(rows[0], { offset: 32, hex: ['4d', '5a', '90', '00'], ascii: 'MZ..' })
  assert.deepEqual(rows[1], { offset: 36, hex: ['41'], ascii: 'A' })
  assert.equal(formatDelay(3000), '3 s')
  assert.equal(formatDelay(-120000), '−2 min')
  assert.equal(formatDelay(null), '')
})

test('mail timeline events carry the verdict as severity', () => {
  const engine = { analyze: () => ({ keywordMatches: [], isAnomalousTime: false, severity: null, isFlagged: false }) }
  const [phish, plain] = mailEvents(
    [
      { sha256: 'a', subject: 'Reset', from: 'x@evil.top', date: 1000, verdict: 'phishing', score: 90 },
      { sha256: 'b', fileName: 'm.eml', importedAt: '2026-11-10T09:00:00Z', verdict: 'clean', score: 0 },
    ],
    engine,
  )
  assert.equal(phish.time, 1000)
  assert.equal(phish.soc.severity, 'high')
  assert.equal(phish.flaggable.key, 'mail:a')
  assert.equal(plain.label, 'm.eml')
  assert.equal(plain.time, Date.parse('2026-11-10T09:00:00Z'))
  assert.equal(plain.soc.severity, null)
})

test('attachment previews and screenshot coordinates', () => {
  assert.equal(previewKind({ size: 10, extension: 'docx', type: { id: 'zip' } }), 'document')
  assert.equal(previewKind({ size: 10, extension: 'bin', type: { id: 'pdf' } }), 'document')
  assert.equal(previewKind({ size: 10, extension: 'htm', type: { id: 'text' } }), 'html')
  assert.equal(previewKind({ size: 10, extension: 'exe', type: { id: 'pe32' } }), null)
  assert.equal(previewKind({ size: 0, extension: 'pdf' }), null)
  const rect = { left: 100, top: 50, width: 640, height: 400 }
  assert.deepEqual(toPagePoint(420, 250, rect, 1280, 800), { x: 640, y: 400 })
  assert.deepEqual(toPagePoint(0, 0, rect, 1280, 800), { x: 0, y: 0 })
})
