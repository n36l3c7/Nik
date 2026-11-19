import assert from 'node:assert/strict'
import { test } from 'node:test'
import { DEFAULT_SORT } from './incidentList.js'
import { filterPayload, filterView, groupFilters, isChanged, menuLabel, nameProblem } from './savedFilters.js'

const FILTERS = [
  { id: 'f1', name: 'my open ones', mine: true, shared: false, query: 'status:open', sort: null, columns: [] },
  { id: 'f2', name: 'Closed last 30 days', mine: false, shared: true, owner: 'admin', query: 'status:closed' },
  {
    id: 'f3',
    name: 'Phishing this week',
    mine: true,
    shared: true,
    query: 'type:Phishing',
    sort: { key: 'severity', dir: 'desc' },
    columns: ['number', 'name', 'severity'],
  },
  { id: 'f4', name: 'Unassigned, high', mine: false, shared: true, owner: 'admin', query: 'owner:""' },
]

test('the menu lists one’s own filters, then those others shared, each by name', () => {
  const groups = groupFilters(FILTERS)
  assert.deepEqual(
    groups.mine.map((filter) => filter.id),
    ['f1', 'f3'],
  )
  // One of mine that is shared stays among mine.
  assert.deepEqual(
    groups.shared.map((filter) => filter.id),
    ['f2', 'f4'],
  )
  assert.deepEqual(groupFilters(null), { mine: [], shared: [] })
  assert.equal(menuLabel(FILTERS[0]), 'Filter: my open ones')
  assert.equal(menuLabel(null), 'Filter: none')
})

test('choosing a filter puts its query, its order and its columns on screen', () => {
  assert.deepEqual(filterView(FILTERS[2]), {
    query: 'type:Phishing',
    sort: { key: 'severity', dir: 'desc' },
    columns: ['number', 'name', 'severity'],
  })
  // One saved with no order and no columns: the order of the list, the person's own columns.
  assert.deepEqual(filterView(FILTERS[0]), { query: 'status:open', sort: DEFAULT_SORT, columns: null })
})

test('a filter is marked as changed when the screen is no longer what it keeps', () => {
  const [plain, , full] = FILTERS
  const screen = { query: 'status:open', sort: DEFAULT_SORT, columns: ['number', 'name'] }
  assert.equal(isChanged(null, screen), false)
  assert.equal(isChanged(plain, screen), false)
  assert.equal(isChanged(plain, { ...screen, query: '  status:open ' }), false)
  assert.equal(isChanged(plain, { ...screen, query: 'status:open severity:high' }), true)
  assert.equal(isChanged(plain, { ...screen, sort: { key: 'name', dir: 'asc' } }), true)
  // It keeps no columns: whatever columns are on screen are the person's own.
  assert.equal(isChanged(plain, { ...screen, columns: ['name'] }), false)
  const kept = {
    query: 'type:Phishing',
    sort: { key: 'severity', dir: 'desc' },
    columns: ['number', 'name', 'severity'],
  }
  assert.equal(isChanged(full, kept), false)
  assert.equal(isChanged(full, { ...kept, columns: ['name', 'number', 'severity'] }), true)
})

test('what is saved is what is on screen', () => {
  assert.deepEqual(filterPayload({ name: ' Mine ', query: ' status:open ', sort: null, columns: ['number', 'name'] }), {
    name: 'Mine',
    query: 'status:open',
    sort: DEFAULT_SORT,
    columns: ['number', 'name'],
  })
  // Saved over the one that is chosen: its name is not sent.
  assert.ok(!('name' in filterPayload({ query: '', sort: { key: 'name', dir: 'asc' }, columns: [] })))
})

test('a name is needed, and is not one of mine already', () => {
  assert.equal(nameProblem('  ', FILTERS), 'A filter needs a name')
  assert.equal(nameProblem('My Open Ones', FILTERS), 'You have a filter with this name already')
  assert.equal(nameProblem('My Open Ones', FILTERS, 'f1'), null) // the one being renamed
  assert.equal(nameProblem('Unassigned, high', FILTERS), null) // someone else's name is free for me
  assert.match(nameProblem('x'.repeat(81), FILTERS), /80 characters/)
  assert.equal(nameProblem('New', null), null)
})
