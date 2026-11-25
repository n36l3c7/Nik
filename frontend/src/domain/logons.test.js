import test from 'node:test'
import assert from 'node:assert/strict'
import {
  LOGON_TYPES,
  OUTCOME_OPTIONS,
  TYPE_OPTIONS,
  apiFilters,
  clickText,
  graphFilters,
  logonTypeLabel,
  logonTypeName,
  outcomeOf,
  sourceText,
  userText,
  withClick,
} from './logons.js'

test('a logon type is called by its name', () => {
  assert.equal(logonTypeName(2), 'interactive')
  assert.equal(logonTypeName('3'), 'network')
  assert.equal(logonTypeName(10), 'remote interactive')
  assert.equal(logonTypeName(11), 'cached')
  assert.equal(logonTypeName(99), '99')
  assert.equal(logonTypeName(null), '')
  assert.equal(logonTypeLabel(8), 'network cleartext (8)')
  assert.deepEqual(Object.keys(LOGON_TYPES), ['2', '3', '4', '5', '7', '8', '9', '10', '11'])
  assert.equal(TYPE_OPTIONS.length, 10)
  assert.equal(TYPE_OPTIONS[0].value, '')
})

test('an outcome has a word and a colour, and an unknown one is shown as it is', () => {
  assert.equal(outcomeOf('failure').color, 'red')
  assert.equal(outcomeOf('success').color, 'emerald')
  assert.deepEqual(outcomeOf('odd'), { label: 'odd', color: 'slate' })
  assert.deepEqual(outcomeOf(null), { label: '—', color: 'slate' })
  assert.deepEqual(
    OUTCOME_OPTIONS.map((item) => item.value),
    ['', 'success', 'failure', 'logoff', 'explicit', 'privileged'],
  )
})

test('where a logon came from and who made it', () => {
  assert.equal(sourceText({ sourceHost: 'ws-01', sourceIp: '10.0.0.5' }), 'ws-01 (10.0.0.5)')
  assert.equal(sourceText({ sourceHost: '', sourceIp: '10.0.0.5' }), '10.0.0.5')
  assert.equal(sourceText({ sourceHost: 'WS-01', sourceIp: 'ws-01' }), 'WS-01')
  assert.equal(sourceText({}), '')
  assert.equal(userText({ user: 'j.alvarez', domain: 'CORP' }), 'CORP\\j.alvarez')
  assert.equal(userText({ user: 'root', domain: '' }), 'root')
  assert.equal(userText({}), '')
})

test('the filters of the table drop what is empty', () => {
  assert.deepEqual(apiFilters({ user: 'a', outcome: '', logonType: '3', flagged: false }), {
    user: 'a',
    logonType: '3',
  })
})

test('the graph takes the time range, type, outcome and user of the table, and a minimum count above one', () => {
  const filters = { from: 1, to: 2, logonType: '3', outcome: 'failure', user: 'a', host: 'srv', q: 'x' }
  assert.deepEqual(graphFilters(filters, 5), {
    from: 1,
    to: 2,
    logonType: '3',
    outcome: 'failure',
    user: 'a',
    minCount: 5,
  })
  assert.deepEqual(graphFilters({ q: 'x' }, 1), {})
  assert.deepEqual(graphFilters(undefined, 0), {})
})

test('a click in the graph replaces the host and source filters of an earlier click', () => {
  const before = { user: 'a', host: 'srv-01', sourceHost: 'ws-01' }
  assert.deepEqual(withClick(before, { sourceIp: '10.0.0.9', host: 'srv-02' }), {
    user: 'a',
    sourceIp: '10.0.0.9',
    host: 'srv-02',
  })
  assert.deepEqual(withClick(before, {}), { user: 'a' })
  assert.equal(clickText({ sourceHost: 'ws-01', host: 'srv-02' }), 'from ws-01 to srv-02')
  assert.equal(clickText({ sourceIp: '10.0.0.9' }), 'from 10.0.0.9')
  assert.equal(clickText({ host: 'srv-02' }), 'to srv-02')
  assert.equal(clickText({}), '')
})
