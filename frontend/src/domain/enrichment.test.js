import test from 'node:test'
import assert from 'node:assert/strict'
import { LOOKUP_TYPES, reputationRank, typeGroups, verdictMeta } from './enrichment.js'

test('verdicts, ranking and type groups', () => {
  assert.equal(verdictMeta('malicious').color, 'red')
  assert.equal(verdictMeta('nope').label, 'unknown')
  assert.ok(
    reputationRank({ verdict: 'malicious', flagged: 1 }) > reputationRank({ verdict: 'suspicious', flagged: 5 }),
  )
  assert.ok(reputationRank({ verdict: 'unknown' }) > reputationRank(null))
  assert.equal(typeGroups(['ip', 'domain', 'url', 'md5', 'sha256']), 'IP · domain · URL · hash')
  assert.ok(!LOOKUP_TYPES.has('email'))
})

test('the indicator permalink round-trips, URLs included', async () => {
  const { iocFromLocation, iocPath } = await import('./enrichment.js')
  const url = 'https://login-paypa1.top/x?a=1&b=2#frag'
  const path = iocPath('url', url)
  assert.ok(path.startsWith('/ioc/url?v=https%3A%2F%2F'))
  const [pathname, search] = path.split('?')
  assert.deepEqual(iocFromLocation({ pathname, search: `?${search}` }), { type: 'url', value: url })
  assert.deepEqual(iocFromLocation({ pathname: '/ioc/ip', search: '?v=185.220.101.47' }), {
    type: 'ip',
    value: '185.220.101.47',
  })
  assert.equal(iocFromLocation({ pathname: '/ioc/ip', search: '' }), null)
  assert.equal(iocFromLocation({ pathname: '/ioc/password', search: '?v=x' }), null)
  assert.equal(iocFromLocation({ pathname: '/incident/abc', search: '?v=x' }), null)
})

test('score bar, retention wording and what changed over time', async () => {
  const { countsLine, retentionLabel, reputationRank, verdictChanges, verdictShares } = await import('./enrichment.js')
  const counts = { malicious: 3, suspicious: 2, harmless: 0, unknown: 1 }
  assert.deepEqual(
    verdictShares(counts).map((s) => [s.verdict, Math.round(s.share)]),
    [
      ['malicious', 50],
      ['suspicious', 33],
      ['unknown', 17],
    ],
  )
  assert.equal(countsLine(counts), '3 malicious · 2 suspicious · 1 unknown')
  assert.deepEqual(verdictShares({}), [])
  assert.equal(retentionLabel(30), '30 days')
  assert.equal(retentionLabel(180), '6 months')
  assert.equal(retentionLabel(365), '1 year')
  assert.equal(retentionLabel(1), '1 day')
  // Newest first in, oldest first out, repeats dropped.
  const history = [{ verdict: 'malicious' }, { verdict: 'malicious' }, { verdict: 'harmless' }, { verdict: 'harmless' }]
  assert.deepEqual(
    verdictChanges(history).map((h) => h.verdict),
    ['harmless', 'malicious'],
  )
  assert.ok(reputationRank({ verdict: 'malicious', score: 80 }) > reputationRank({ verdict: 'malicious', score: 55 }))
})

test('the menu offers to analyse a value, or to open its analysis', async () => {
  const { addressOf, analysisActions, analysisColor, analysisLabel } = await import('./enrichment.js')
  assert.equal(addressOf('domain', 'evil.example'), 'https://evil.example/')
  assert.equal(addressOf('ip', '1.2.3.4'), null)

  // Not asked yet, or not analysed: an address can be visited.
  assert.deepEqual(
    analysisActions('url', 'https://a.example/x').map((a) => [a.id, a.label]),
    [['analyse', 'Analyse URL']],
  )
  assert.deepEqual(analysisActions('domain', 'a.example', { artifacts: [], canAnalyse: true })[0], {
    id: 'analyse',
    label: 'Analyse as URL',
    hint: 'https://a.example/',
    address: 'https://a.example/',
  })
  // An internal name is never offered; a hash cannot be "analysed" from its value.
  assert.deepEqual(analysisActions('domain', 'fileserver.corp', { artifacts: [], canAnalyse: false }), [])
  assert.deepEqual(analysisActions('sha256', 'a'.repeat(64), { artifacts: [] }), [])
  assert.deepEqual(analysisActions('ip', '1.2.3.4', { artifacts: [] }), [])
  assert.deepEqual(analysisActions('email', 'a@b.example'), [])

  const scan = { id: 'url-1', kind: 'url', verdict: 'phishing', score: 82, status: 'done' }
  assert.deepEqual(
    analysisActions('url', 'https://a.example/x', { artifacts: [scan] }).map((a) => [a.id, a.hint]),
    [
      ['open', 'phishing 82'],
      ['rescan', undefined],
    ],
  )
  // A domain's analysis is a page on it: opened, not scanned again from here.
  assert.deepEqual(
    analysisActions('domain', 'a.example', { artifacts: [scan] }).map((a) => a.id),
    ['open'],
  )
  const file = { id: 'file-1', kind: 'file', verdict: 'high', score: null }
  assert.deepEqual(
    analysisActions('sha256', 'a'.repeat(64), { artifacts: [file] }).map((a) => [a.id, a.hint]),
    [['open', 'high']],
  )
  assert.equal(analysisLabel({ kind: 'url', verdict: '', score: 0, status: 'done' }), 'clean 0')
  assert.equal(analysisLabel({ kind: 'url', verdict: '', status: 'running' }), 'running')
  assert.equal(analysisLabel({ kind: 'file', verdict: '' }), 'no rule match')
  assert.equal(analysisColor(scan), 'red')
  assert.equal(analysisColor({ verdict: 'medium' }), 'amber')
  assert.equal(analysisColor({ verdict: 'clean' }), 'slate')
})

test('a source of Settings says how it stands, and what turning it on takes', async () => {
  const { limitsLine, sourceState } = await import('./enrichment.js')
  assert.equal(limitsLine({ perMinute: 4, perDay: 500, cacheHours: 24 }), '4 a minute · 500 a day · answers kept 24 h')
  assert.equal(limitsLine({ perMinute: 0, perDay: 0, cacheHours: 0 }), '')
  assert.equal(limitsLine(null), '')
  const on = sourceState({
    on: true,
    instance: 'VirusTotal',
    keys: 2,
    limits: { perMinute: 4, perDay: 500, cacheHours: 0 },
  })
  assert.equal(on.state, 'on')
  assert.equal(on.line, 'Asked through the instance “VirusTotal”, 2 keys in rotation · 4 a minute · 500 a day')
  assert.ok(sourceState({ on: true, instance: 'RDAP', keys: 1, limits: {} }).line.endsWith('no limit set'))
  assert.equal(sourceState({ on: false, instances: 2 }).state, 'off')
  const free = sourceState({ on: false, instances: 0, needsNothing: true })
  assert.equal(free.state, 'none')
  assert.ok(free.line.includes('turned on here'))
  assert.ok(sourceState({ on: false, instances: 0, needsNothing: false }).line.includes('in Connectors'))
})

test('a key kept from before 6.5 says what it waits for', async () => {
  const { oldKeyLine } = await import('./enrichment.js')
  const waiting = {
    state: 'waiting',
    connectors: [
      { id: 'threatfox', installed: true },
      { id: 'urlhaus', installed: false },
    ],
  }
  assert.equal(
    oldKeyLine(waiting),
    'It moves to an instance by itself when the pack urlhaus is installed (Content packs).',
  )
  const both = {
    state: 'waiting',
    connectors: [
      { id: 'urlhaus', installed: false },
      { id: 'malwarebazaar', installed: false },
    ],
  }
  assert.ok(oldKeyLine(both).includes('the packs urlhaus, malwarebazaar are installed'))
  assert.ok(oldKeyLine({ state: 'rejected', connectors: [] }).startsWith('The vendor had refused this key'))
  assert.ok(oldKeyLine({ state: 'unreadable', connectors: [] }).includes('SECRET_KEY'))
  assert.ok(
    oldKeyLine({ state: 'waiting', connectors: [{ id: 'otx', installed: true }] }).startsWith(
      'It could not be moved to otx',
    ),
  )
})
