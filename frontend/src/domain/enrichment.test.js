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
