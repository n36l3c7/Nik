import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  bulkBody,
  bulkText,
  changedText,
  cutText,
  errorText,
  errorsOf,
  incidentHref,
  listParams,
  logSourceText,
  packLabel,
  packOptions,
  pageOf,
  positionOf,
  ruleFilters,
  shownMatches,
  sigmaDate,
  starterRule,
  summaryLine,
  tryText,
} from './sigma.js'

test('the filters of the table are what the API takes: empty left out, booleans and numbers typed', () => {
  assert.deepEqual(ruleFilters({ q: 'rdp', level: '4', enabled: 'true', supported: 'false', pack: '', host: 'x' }), {
    q: 'rdp',
    level: 4,
    enabled: true,
    supported: false,
  })
  assert.deepEqual(ruleFilters({}), {})
})

test('a page is asked by the offset the cursor holds', () => {
  assert.deepEqual(listParams({ filters: { q: 'a' }, order: '-level', cursor: '100', limit: 50 }), {
    q: 'a',
    order: '-level',
    limit: 50,
    offset: 100,
  })
  assert.equal(listParams({}).offset, 0)
  assert.equal(listParams({ cursor: 'junk', limit: 9999 }).limit, 500)
})

test('the next cursor is the next offset while there is more', () => {
  assert.deepEqual(pageOf({ rules: [1, 2], total: 5, offset: 0 }), { items: [1, 2], next: '2', total: 5 })
  assert.equal(pageOf({ rules: [1, 2], total: 4, offset: 2 }).next, null)
})

test('a bulk switch names the chosen ids, or the filters for "all that match"', () => {
  assert.deepEqual(bulkBody(true, { all: false, ids: ['a', 'b'] }), { enabled: true, ids: ['a', 'b'] })
  assert.deepEqual(bulkBody(false, { all: true, filters: { level: '4', q: '' } }), {
    enabled: false,
    filters: { level: 4 },
  })
  assert.equal(bulkText(true, { matched: 0, changed: 0 }), 'No rule matched.')
  assert.equal(bulkText(true, { matched: 10, changed: 7 }), '7 of 10 rules switched on. 3 left as they were.')
  assert.equal(bulkText(false, { matched: 2, changed: 2 }), '2 of 2 rules switched off.')
})

test('the line over the list counts rules, what is on, what Nik cannot run and the levels', () => {
  const summary = {
    total: 2731,
    enabled: 214,
    supported: 2700,
    unchecked: 0,
    engine: '1',
    byLevel: { 1: 0, 2: 5, 3: 100, 4: 40, 5: 3 },
  }
  assert.equal(
    summaryLine(summary),
    '2,731 rules · 214 on · 31 Nik cannot run · 3 critical, 40 high, 100 medium, 5 low · engine 1',
  )
  assert.equal(summaryLine({ total: 1, enabled: 0, supported: 1, byLevel: {} }), '1 rule · 0 on')
  assert.equal(summaryLine(null), '')
})

test('the pack choices put the rules written here beside the packs', () => {
  const summary = { packs: [{ id: '', name: 'Written here' }, { id: 'nik', name: 'Nik' }, { id: 'sigmahq' }] }
  assert.deepEqual(
    packOptions(summary).map((option) => option.value),
    ['', '-', 'nik', 'sigmahq'],
  )
  assert.equal(packLabel({ pack: '' }, summary), 'Written here')
  assert.equal(packLabel({ pack: 'nik' }, summary), 'Nik')
  assert.equal(packLabel({ pack: 'x' }, summary), 'x')
  assert.equal(logSourceText({ product: 'windows', category: 'process_creation' }), 'windows / process_creation')
  assert.equal(logSourceText({}), '—')
})

test('a new rule starts from a valid-looking text with a fresh id and the date of the day', () => {
  const text = starterRule({ id: '11111111-2222-4333-8444-555555555555', now: new Date(2026, 10, 5) })
  assert.match(text, /^title: .+\nid: 11111111-2222-4333-8444-555555555555\n/)
  assert.match(text, /date: 2026\/11\/05\n/)
  assert.match(text, /logsource:\n {4}product: windows/)
  assert.match(text, /condition: selection/)
  assert.notEqual(starterRule().split('\n')[1], starterRule().split('\n')[1])
  assert.equal(sigmaDate(new Date(2026, 0, 2)), '2026/01/02')
})

test('an error of the worker is placed by its line and column, kept inside the text', () => {
  const text = 'title: a\nid: b\nlevel: x'
  assert.deepEqual(positionOf(text, 1, 1), { from: 0, to: 8 })
  assert.deepEqual(positionOf(text, 2, 5), { from: 13, to: 14 })
  assert.deepEqual(positionOf(text, 3, 0), { from: 15, to: 23 })
  assert.deepEqual(positionOf(text, 99, 1), { from: 15, to: 23 }) // past the end: the last line
  assert.deepEqual(positionOf(text, 2, 99), { from: 14, to: 14 }) // past the line: its end
  assert.deepEqual(positionOf('', 1, 1), { from: 0, to: 0 })
  assert.equal(errorText({ line: 3, message: 'a rule needs an id' }), 'Line 3: a rule needs an id')
})

test('errors are read from a refused request, and only from one', () => {
  assert.deepEqual(errorsOf({ data: { errors: [{ line: 1, message: 'x' }] } }), [{ line: 1, message: 'x' }])
  assert.deepEqual(errorsOf({ data: { errors: [] } }), [])
  assert.deepEqual(errorsOf(new Error('boom')), [])
})

test('only a real change of the text counts as one', () => {
  assert.equal(changedText('a\n', 'a'), false)
  assert.equal(changedText('a', 'b'), true)
})

test('a try says what it scanned, what it found and why it stopped', () => {
  assert.equal(tryText({ scanned: 4310, matchCount: 2 }), 'Scanned 4,310 records: 2 matches.')
  assert.equal(tryText({ scanned: 1, matchCount: 1 }), 'Scanned 1 record: 1 match.')
  assert.equal(cutText({ cut: false }), '')
  assert.match(cutText({ cut: true, cutReason: 'time', limits: { seconds: 60 } }), /after 60 seconds/)
  assert.match(cutText({ cut: true, cutReason: 'records', limits: { records: 200000 } }), /at 200,000 records/)
  const shown = shownMatches({ matchCount: 1000, matches: new Array(300).fill({}) }, 200)
  assert.equal(shown.items.length, 200)
  assert.equal(shown.more, 800)
  assert.equal(incidentHref('a b'), '/incident/a%20b')
})
