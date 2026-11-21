import test from 'node:test'
import assert from 'node:assert/strict'
import {
  groupRows,
  needingAttention,
  scrapeConfig,
  stateBadge,
  summary,
  thresholdsBody,
  thresholdsForm,
  thresholdsProblem,
} from './health.js'

const row = (id, group, state) => ({ id, group, state, label: id, value: 'v', detail: '', link: '', since: null })
const ROWS = [
  row('disk.store', 'Disk', 'fine'),
  row('disk.backups', 'Disk', 'attention'),
  row('queue.mirror', 'Queues', 'fine'),
  row('tls.certificate', 'Certificate', 'unknown'),
  row('audit.chain', 'Audit log', 'problem'),
  row('audit.forwarding', 'Audit log', 'attention'),
]

test('rows are grouped in the order they come, each group with its worst state', () => {
  const groups = groupRows(ROWS)
  assert.deepEqual(
    groups.map((group) => [group.name, group.rows.length, group.worst]),
    [
      ['Disk', 2, 'attention'],
      ['Queues', 1, 'fine'],
      ['Certificate', 1, 'fine'],
      ['Audit log', 2, 'problem'],
    ],
  )
  assert.deepEqual(groupRows(), [])
})

test('what needs attention is listed with the problems first', () => {
  assert.deepEqual(
    needingAttention(ROWS).map((found) => found.id),
    ['audit.chain', 'disk.backups', 'audit.forwarding'],
  )
  assert.deepEqual(needingAttention([row('a', 'A', 'fine'), row('b', 'A', 'unknown')]), [])
})

test('the page is summed up in one sentence', () => {
  assert.equal(
    summary({ fine: 20, attention: 0, problem: 0, unknown: 0 }),
    'Everything that could be measured is fine.',
  )
  assert.equal(
    summary({ fine: 20, attention: 2, problem: 1, unknown: 1 }),
    '1 problem, 2 things need attention. 1 could not be measured.',
  )
  assert.equal(summary({ attention: 1 }), '1 thing needs attention.')
  assert.equal(summary({ problem: 3 }), '3 problems.')
})

test('a state the page does not know is shown as not known', () => {
  assert.deepEqual(stateBadge('problem'), { color: 'red', text: 'problem' })
  assert.deepEqual(stateBadge('whatever'), { color: 'slate', text: 'not known' })
})

const THRESHOLDS = [
  { name: 'diskAttentionPercent', value: 80, default: 80, min: 1, max: 99, label: 'A disk needs attention' },
  { name: 'diskProblemPercent', value: 90, default: 90, min: 1, max: 100, label: 'A disk is a problem' },
]

test('the thresholds are typed, checked, and only the changed ones are sent', () => {
  const form = thresholdsForm(THRESHOLDS)
  assert.deepEqual(form, { diskAttentionPercent: '80', diskProblemPercent: '90' })
  assert.equal(thresholdsProblem(form, THRESHOLDS), null)
  assert.deepEqual(thresholdsBody(form, THRESHOLDS), {})
  assert.deepEqual(thresholdsBody({ ...form, diskAttentionPercent: ' 70 ' }, THRESHOLDS), { diskAttentionPercent: 70 })
  for (const typed of ['', '0', '100', '7.5', 'many', '-3']) {
    assert.equal(
      thresholdsProblem({ ...form, diskAttentionPercent: typed }, THRESHOLDS),
      'A disk needs attention: a whole number from 1 to 99.',
      typed,
    )
  }
})

test('the scrape job names the address Nik is used at', () => {
  const config = scrapeConfig('https://nik.corp.example:8443')
  assert.match(config, /scheme: https\n/)
  assert.match(config, /metrics_path: \/api\/metrics\n/)
  assert.match(config, /credentials_file: \/etc\/prometheus\/nik-metrics-token\n/)
  assert.match(config, /- targets: \["nik\.corp\.example:8443"\]$/)
  // The token itself is never in what is copied.
  assert.doesNotMatch(config, /nikm_/)
  assert.match(scrapeConfig('not an address'), /targets: \["nik\.example:8443"\]/)
})
