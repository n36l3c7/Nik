import test from 'node:test'
import assert from 'node:assert/strict'
import { guessIocType, sourceLabel } from './iocs.js'

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
