import assert from 'node:assert/strict'
import { test } from 'node:test'
import { evidenceAddress, sameAddress, stripRemoteCss } from './links.js'

test('only an http(s) address from the evidence can be opened', () => {
  assert.deepEqual(evidenceAddress('https://evil.top/login?x=1'), {
    href: 'https://evil.top/login?x=1',
    scheme: 'https',
    defanged: 'hxxps[:]//evil[.]top/login?x=1',
  })
  assert.equal(evidenceAddress('  HTTP://Evil.Top  ').href, 'http://evil.top/')
  for (const url of [
    'javascript:alert(1)',
    'data:text/html,<script>1</script>',
    'file:///C:/Windows/win.ini',
    'chrome://settings',
    'evil.top/no-scheme',
    'http://',
    '',
    null,
  ]) {
    assert.equal(evidenceAddress(url).href, null, String(url))
  }
  assert.equal(evidenceAddress('javascript:alert(1)').scheme, 'javascript')
})

test('remote references are removed from CSS, embedded images kept', () => {
  assert.equal(stripRemoteCss('background:url(https://t.example/p?id=42) no-repeat'), 'background:none no-repeat')
  assert.equal(stripRemoteCss("background-image: URL( '//t.example/p.gif' )"), 'background-image: none')
  assert.equal(
    stripRemoteCss('background:url(data:image/png;base64,AAAA)'),
    'background:url(data:image/png;base64,AAAA)',
  )
  assert.equal(stripRemoteCss('@import url("https://x/y.css"); p{color:red}'), ' p{color:red}')
  assert.equal(stripRemoteCss("@import 'https://x/y.css';p{}"), 'p{}')
  assert.equal(stripRemoteCss('color: red'), 'color: red')
  assert.equal(stripRemoteCss(null), '')
})

test('a tracking pixel is recognised however its address is spelled', () => {
  assert.equal(sameAddress(' https://t.example/p.gif\n', 'https://t.example/p.gif'), true)
  assert.equal(sameAddress('//t.example/p.gif', 'https://t.example/p.gif'), true)
  assert.equal(sameAddress('https://t.example/other.gif', 'https://t.example/p.gif'), false)
})
