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

test('the scripts of a page are listed worst first and named by where they come from', async () => {
  const { codeSegments, scriptBadge, scriptName, scriptStats, sortScripts } = await import('./urlscan.js')
  const scripts = [
    {
      kind: 'external',
      url: 'https://cdnjs.cloudflare.com/jquery.min.js',
      host: 'cdnjs.cloudflare.com',
      thirdParty: true,
      library: 'jQuery 3.7.1',
    },
    { kind: 'inline', name: 'inline #1', findings: [{ id: 'obf.eval-decode' }], severity: 'medium', obfuscation: 40 },
    {
      kind: 'external',
      url: 'https://evil.example/assets/app.min.js?v=2',
      host: 'evil.example',
      findings: [{ id: 'a' }, { id: 'b' }],
      severity: 'high',
    },
    { kind: 'inline', name: 'inline #2' },
  ]
  const sorted = sortScripts(scripts)
  assert.deepEqual(
    sorted.map((script) => script.index),
    [2, 1, 3, 0],
  )
  assert.equal(scriptName(sorted[0]), '/assets/app.min.js?v=2')
  assert.equal(scriptName(sorted[1]), 'inline #1')
  assert.deepEqual(scriptBadge(sorted[0]), { color: 'red', label: '2 findings' })
  assert.deepEqual(scriptBadge(sorted[1]), { color: 'amber', label: '1 finding' })
  assert.deepEqual(scriptBadge(sorted[2]), { color: 'slate', label: 'clean' })
  assert.deepEqual(scriptBadge(sorted[3]), { color: 'emerald', label: 'known library' })
  assert.deepEqual(scriptStats(scripts), {
    total: 4,
    external: 2,
    inline: 2,
    flagged: 2,
    high: 1,
    obfuscated: 1,
    hosts: 1,
  })

  const parts = codeSegments('abc fetch(x) def eval(y)', [
    { id: 'two', start: 17, end: 24 },
    { id: 'one', start: 4, end: 12 },
    { id: 'inside', start: 6, end: 9 },
    { id: 'whole', start: 0, end: 0 },
  ])
  assert.deepEqual(parts, [
    { text: 'abc ' },
    { text: 'fetch(x)', finding: 'one' },
    { text: ' def ' },
    { text: 'eval(y)', finding: 'two' },
  ])
  assert.deepEqual(codeSegments('plain', []), [{ text: 'plain' }])
})

test('minified code is laid out to be read, with the marks on the same text', async () => {
  const { beautifySegments, codeSegments, looksMinified } = await import('./urlscan.js')
  const code =
    "function a(b){if(b){fetch('https://x.example/a;b{c}',{method:'POST'});return 1}for(var i=0;i<3;i++){c(i)}}// done; {\nvar z=`t{1};`;"
  const start = code.indexOf('fetch(')
  const segments = codeSegments(code, [{ id: 'send', start, end: start + 35 }])
  const laid = beautifySegments(segments)
  const text = laid.map((part) => part.text).join('')
  assert.equal(
    text,
    [
      'function a(b){',
      '  if(b){',
      "    fetch('https://x.example/a;b{c}',{",
      "      method:'POST'",
      '    });',
      '    return 1',
      '  }',
      '  for(var i=0;i<3;i++){',
      '    c(i)',
      '  }',
      '}',
      '// done; {',
      'var z=`t{1};`;',
      '',
    ].join('\n'),
  )
  // Only white space changed, and the mark still covers the call.
  assert.equal(text.replace(/\s+/g, ''), code.replace(/\s+/g, ''))
  const marked = laid.filter((part) => part.finding)
  assert.equal(marked.length, 1)
  assert.equal(marked[0].text.replace(/\s+/g, ''), code.slice(start, start + 35).replace(/\s+/g, ''))

  // Statements of a callback passed to a call are statements too; "for (;;)" stays on its line.
  const callback = beautifySegments([{ text: "on('x',function(e){var u=1;send(u);for(;;){}});" }])[0].text
  assert.equal(callback, ["on('x',function(e){", '  var u=1;', '  send(u);', '  for(;;){', '  }', '});', ''].join('\n'))

  assert.equal(looksMinified('a;'.repeat(400)), true)
  assert.equal(looksMinified('var a = 1\n'.repeat(100)), false)
  assert.equal(looksMinified('short'), false)
})
