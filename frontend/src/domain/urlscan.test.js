import assert from 'node:assert/strict'
import { test } from 'node:test'
import { displayUrl, isScanning, scanBadge, urlEvents, urlFromText } from './urlscan.js'

test('the badge shows the state until there is a verdict', () => {
  assert.deepEqual(scanBadge({ status: 'queued' }), { label: 'scanning…', color: 'cyan' })
  assert.equal(isScanning({ status: 'running' }), true)
  assert.deepEqual(scanBadge({ status: 'error' }), { label: 'not visited', color: 'amber' })
  assert.deepEqual(scanBadge({ status: 'done', verdict: 'phishing', score: 85 }), {
    label: 'phishing · 85',
    color: 'red',
  })
  assert.deepEqual(scanBadge({ status: 'done', verdict: 'clean', score: 0 }), { label: 'clean · 0', color: 'slate' })
})

test('an address is recognised in pasted text, defanged or bare', () => {
  assert.equal(urlFromText('https://login-paypa1.top/signin?id=1'), 'https://login-paypa1.top/signin?id=1')
  assert.equal(urlFromText('  hxxps://login-paypa1[.]top/signin '), 'https://login-paypa1.top/signin')
  assert.equal(urlFromText('evil.top/x'), 'https://evil.top/x')
  assert.equal(urlFromText('example.com'), 'https://example.com/')
  assert.equal(urlFromText('http://203.0.113.10/a'), 'http://203.0.113.10/a')
})

test('ordinary text is not taken for an address', () => {
  for (const text of [
    'hello',
    'two words.com',
    'file',
    'ftp://example.com/x',
    'javascript:alert(1)',
    '',
    'a'.repeat(3000),
  ]) {
    assert.equal(urlFromText(text), null, text)
  }
})

test('the display form drops the scheme and the query', () => {
  assert.equal(displayUrl('https://login-paypa1.top/signin?id=8841'), 'login-paypa1.top/signin')
  assert.equal(displayUrl('https://example.com/'), 'example.com')
  assert.equal(displayUrl('not a url'), 'not a url')
})

test('finished scans are timeline events, with the verdict as severity', () => {
  const engine = { analyze: () => ({ severity: null, isFlagged: false, reasons: [] }) }
  const scans = [
    {
      id: 'a',
      url: 'https://evil.top/x',
      status: 'done',
      verdict: 'phishing',
      score: 90,
      scannedAt: '2026-11-11T10:00:00Z',
    },
    { id: 'b', url: 'https://example.com/', status: 'queued' },
    {
      id: 'c',
      url: 'https://example.org/',
      status: 'done',
      verdict: 'clean',
      score: 0,
      scannedAt: '2026-11-11T11:00:00Z',
    },
  ]
  const events = urlEvents(scans, engine)
  assert.deepEqual(
    events.map((e) => [e.id, e.soc.severity, e.label]),
    [
      ['url:a', 'high', 'evil.top/x'],
      ['url:c', null, 'example.org'],
    ],
  )
  assert.equal(events[0].flaggable.key, 'url:a')
})
