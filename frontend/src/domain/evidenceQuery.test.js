import assert from 'node:assert/strict'
import { test } from 'node:test'
import { queryString, recordFilters } from './evidenceQuery.js'

test('the query string leaves out what is empty and writes true as true', () => {
  assert.equal(queryString({}), '')
  assert.equal(queryString({ kind: '', level: null, flagged: false }), '')
  assert.equal(
    queryString({ kind: 'eventlog', eventId: 4688, flagged: true }),
    '?kind=eventlog&eventId=4688&flagged=true',
  )
  // Zero is a value (an offset), not an empty one.
  assert.equal(queryString({ offset: 0 }), '?offset=0')
  assert.equal(queryString({ q: 'a b&c' }), '?q=a+b%26c')
})

test('only the filters the API knows are kept', () => {
  assert.deepEqual(recordFilters({ host: 'H1', q: '', unknown: 'x', level: 3, flagged: false }), {
    host: 'H1',
    level: 3,
  })
  assert.deepEqual(recordFilters(undefined), {})
})

test('a list repeats its name, and the data filters may be lists', () => {
  assert.equal(
    queryString({
      dataKey: ['inUse', 'ads'],
      dataValue: ['false', 'true'],
      dataHas: ['reasons:CLOSE'],
      kindNot: 'disk',
    }),
    '?dataKey=inUse&dataKey=ads&dataValue=false&dataValue=true&dataHas=reasons%3ACLOSE&kindNot=disk',
  )
  assert.equal(queryString({ dataKey: [] }), '')
  assert.deepEqual(recordFilters({ dataHas: ['a:b'], dataKey: [] }), { dataHas: ['a:b'] })
})
