import test from 'node:test'
import assert from 'node:assert/strict'
import { allowlistOptions, defang, guessIocType, sourceLabel } from './iocs.js'

test('guessIocType recognises each indicator type', () => {
  assert.equal(guessIocType('185.220.101.47'), 'ip')
  assert.equal(guessIocType('fe80::1'), 'ip')
  assert.equal(guessIocType('http://x.top/a'), 'url')
  assert.equal(guessIocType('a@b.ru'), 'email')
  assert.equal(guessIocType('a'.repeat(64)), 'sha256')
  assert.equal(guessIocType('A'.repeat(40)), 'sha1')
  assert.equal(guessIocType('0'.repeat(32)), 'md5')
  assert.equal(guessIocType('cdn-update-service.top'), 'domain')
  assert.equal(guessIocType('LOCAL'), null)
  assert.equal(guessIocType('999.1.1.1'), null)
  assert.equal(guessIocType(''), null)
})

test('sourceLabel names the tab and the source', () => {
  assert.equal(sourceLabel('browser:chrome'), 'Browser · Chrome')
  assert.equal(sourceLabel('commands:powershell'), 'Commands · PowerShell')
  assert.equal(sourceLabel('eventlog:Microsoft-Windows-Sysmon/Operational'), 'Event log · Sysmon')
  assert.equal(sourceLabel('sample:invoice.exe'), 'Sample · invoice.exe')
  assert.equal(sourceLabel('endpoint:persistence'), 'Endpoint · Persistence')
})

test('allowlistOptions offers the value, then wider entries', () => {
  assert.deepEqual(
    allowlistOptions('url', 'https://contoso-my.sharepoint.com/x').map((o) => o.entry),
    ['https://contoso-my.sharepoint.com/x', 'contoso-my.sharepoint.com', 'sharepoint.com'],
  )
  assert.deepEqual(
    allowlistOptions('ip', '185.220.101.47').map((o) => o.entry),
    ['185.220.101.47', '185.220.101.0/24'],
  )
  assert.deepEqual(
    allowlistOptions('email', 'A@Mail.Contoso.it').map((o) => o.entry),
    ['a@mail.contoso.it', 'mail.contoso.it', 'contoso.it'],
  )
  assert.deepEqual(
    allowlistOptions('ip', 'fe80::1').map((o) => o.entry),
    ['fe80::1'],
  )
  assert.deepEqual(
    allowlistOptions('sha256', 'AB').map((o) => o.entry),
    ['ab'],
  )
})

test('defang', () => {
  assert.equal(defang('https://evil.top/a.php'), 'hxxps[:]//evil[.]top/a[.]php')
  assert.equal(defang('185.220.101.47'), '185[.]220[.]101[.]47')
  assert.equal(defang('x@evil.ru'), 'x[@]evil[.]ru')
})

test('indicators are found inside a line, private addresses and file names left as text', async () => {
  const { indicatorSegments, isPublicIp } = await import('./iocs.js')
  const typed = (text, hint) =>
    indicatorSegments(text, hint)
      .filter((part) => part.type)
      .map((part) => `${part.type}:${part.text}`)

  assert.equal(isPublicIp('185.220.101.47'), true)
  for (const address of [
    '10.12.0.44',
    '192.168.1.1',
    '172.20.0.3',
    '127.0.0.1',
    '169.254.1.1',
    '100.64.0.9',
    '224.0.0.251',
    '::1',
    'fe80::1',
  ])
    assert.equal(isPublicIp(address), false, address)

  assert.deepEqual(typed('Destination Address: 185.220.101.47'), ['ip:185.220.101.47'])
  assert.deepEqual(typed('Source Address: 10.12.0.44'), [])
  assert.deepEqual(typed('Host: cdn-update.top'), ['domain:cdn-update.top'])
  assert.deepEqual(typed('Full request URI: http://cdn-update.top/get.php?id=7'), [
    'url:http://cdn-update.top/get.php?id=7',
  ])
  assert.deepEqual(typed('Standard query 0x1a2b A login-microsoftonline.support'), [
    'domain:login-microsoftonline.support',
  ])
  assert.deepEqual(typed('Referer: http://login-microsoftonline.support/.'), [
    'url:http://login-microsoftonline.support/',
  ])
  // Not indicators: files, versions, a URL on a private address, a path.
  assert.deepEqual(typed('GET /get.php?id=7 HTTP/1.1'), [])
  assert.deepEqual(typed('User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0'), [])
  assert.deepEqual(typed('HTTP/1.1 200 OK (application/x-msdownload) invoice.exe'), [])
  assert.deepEqual(typed('Location: http://192.168.1.10/admin'), [])
  assert.deepEqual(typed('Content-Type: text/html; charset=utf-8'), [])
  assert.deepEqual(typed(`sha256 ${'a'.repeat(64)}`), [`sha256:${'a'.repeat(64)}`])

  // The text comes back whole, in order.
  const parts = indicatorSegments('from 10.0.0.1 to 185.220.101.47, then evil.example.org.')
  assert.equal(parts.map((part) => part.text).join(''), 'from 10.0.0.1 to 185.220.101.47, then evil.example.org.')
  assert.deepEqual(
    parts.filter((part) => part.type).map((part) => part.text),
    ['185.220.101.47', 'evil.example.org'],
  )
})
