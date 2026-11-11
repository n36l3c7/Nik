import assert from 'node:assert/strict'
import { test } from 'node:test'
import { recognise, refang } from './pasted.js'

test('defanged text is read as it was meant', () => {
  assert.equal(refang(' hxxps://evil[.]top/x '), 'https://evil.top/x')
  assert.equal(refang('1.2.3[.]4'), '1.2.3.4')
  assert.equal(refang('user[at]evil(.)top'), 'user@evil.top')
  assert.equal(refang('example.com'), 'example.com')
})

test('an address is recognised with its scheme or a path', () => {
  assert.deepEqual(recognise('hxxps://login-paypa1[.]top/signin?id=1'), {
    kind: 'url',
    value: 'https://login-paypa1.top/signin?id=1',
    url: 'https://login-paypa1.top/signin?id=1',
    defanged: true,
  })
  assert.equal(recognise('evil.top/x').url, 'https://evil.top/x')
  assert.equal(recognise('http://203.0.113.10/a').kind, 'url')
  assert.equal(recognise('https://example.com').defanged, false)
})

test('a bare host is a domain that can also be visited', () => {
  assert.deepEqual(recognise('Login-Paypa1.top'), {
    kind: 'domain',
    value: 'login-paypa1.top',
    url: 'https://login-paypa1.top/',
    defanged: false,
  })
})

test('hashes, addresses and e-mail addresses are indicators', () => {
  assert.equal(recognise('A'.repeat(64)).kind, 'sha256')
  assert.equal(recognise('a'.repeat(64)).value, 'a'.repeat(64))
  assert.equal(recognise('b'.repeat(40)).kind, 'sha1')
  assert.equal(recognise('c'.repeat(32)).kind, 'md5')
  assert.deepEqual(recognise('185.220.101[.]47'), { kind: 'ip', value: '185.220.101.47', url: null, defanged: true })
  assert.equal(recognise('service[at]paypai.example').kind, 'email')
  assert.equal(recognise('service@paypai.example').url, null)
})

test('ordinary text is left alone', () => {
  for (const text of [
    'hello',
    'two words',
    'line one\nline two',
    '',
    '12345',
    'ftp://example.com/x',
    'x'.repeat(3000),
  ]) {
    assert.equal(recognise(text), null, JSON.stringify(text.slice(0, 20)))
  }
})
