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
