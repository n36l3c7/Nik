import assert from 'node:assert/strict'
import { test } from 'node:test'
import { archivedParam, canArchive, daysProblem, isArchived } from './archive.js'

test('only a closed incident that is not archived can be archived', () => {
  assert.equal(canArchive({ status: 'closed' }), true)
  assert.equal(canArchive({ status: 'closed', archivedAt: '2026-11-25T10:00:00Z' }), false)
  assert.equal(canArchive({ status: 'open' }), false)
  assert.equal(canArchive(null), false)
  assert.equal(isArchived({ archivedAt: 'x' }), true)
  assert.equal(isArchived({ archivedAt: null }), false)
})

test('the filter sends only what the server does not do by itself', () => {
  assert.equal(archivedParam('exclude'), '')
  assert.equal(archivedParam('only'), 'only')
  assert.equal(archivedParam('include'), 'include')
  assert.equal(archivedParam(undefined), '')
})

test('the days of the rule are a whole number from 1 to 3650', () => {
  assert.equal(daysProblem(180), '')
  assert.equal(daysProblem('30'), '')
  for (const bad of [0, 3651, 1.5, '', 'x', -1]) assert.notEqual(daysProblem(bad), '', String(bad))
})
