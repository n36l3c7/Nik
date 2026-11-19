import assert from 'node:assert/strict'
import { test } from 'node:test'
import { absoluteLink, joinSections, objectMenuItems } from './menus.js'

test('sections are joined by a rule, and an empty one leaves none behind', () => {
  const a = { label: 'A' }
  const b = { label: 'B' }
  assert.deepEqual(joinSections([[a], [b]]), [a, 'separator', b])
  assert.deepEqual(joinSections([[a], [], [null, false], [b]]), [a, 'separator', b])
  assert.deepEqual(joinSections([[], [a, null, b]]), [a, b])
  assert.deepEqual(joinSections([[], null, undefined]), [])
})

test('a path becomes an address that can be pasted elsewhere', () => {
  assert.equal(
    absoluteLink('/automation/playbooks/abc', 'https://nik.example'),
    'https://nik.example/automation/playbooks/abc',
  )
  assert.equal(
    absoluteLink('/settings/lists/all?open=a%20b', 'https://nik.example:8443'),
    'https://nik.example:8443/settings/lists/all?open=a%20b',
  )
  assert.equal(absoluteLink(null, 'https://nik.example'), '')
})

test('the menu of an object: what it offers, what to copy, then what destroys', () => {
  const copied = []
  const context = { copyText: (what, text) => copied.push([what, text]), origin: 'https://nik.example' }
  const open = { label: 'Open', onSelect: () => {} }
  const remove = { label: 'Delete…', onSelect: () => {} }
  const items = objectMenuItems(
    {
      actions: [open, null],
      link: '/tasks/t1',
      copy: [
        { label: 'Copy the name', text: 'Reset passwords' },
        { label: 'Copy the id', text: '' },
      ],
      record: { id: 't1' },
      danger: [remove],
    },
    context,
  )
  assert.deepEqual(
    items.map((item) => (item === 'separator' ? '—' : item.label)),
    ['Open', '—', 'Copy link', 'Copy the name', 'Copy as JSON', '—', 'Delete…'],
  )
  for (const item of items) if (item !== 'separator' && item.label.startsWith('Copy')) item.onSelect()
  assert.deepEqual(copied, [
    ['Link', 'https://nik.example/tasks/t1'],
    ['name', 'Reset passwords'],
    ['JSON', '{\n  "id": "t1"\n}'],
  ])
  // Nothing to offer: no items, and the browser's own menu opens.
  assert.deepEqual(objectMenuItems({}, context), [])
  assert.deepEqual(objectMenuItems({ actions: [open] }, context), [open])
})
