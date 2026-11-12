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
