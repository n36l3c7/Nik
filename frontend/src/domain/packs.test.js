import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  actionBadge,
  byKind,
  choicesOf,
  diffLines,
  idFromName,
  importable,
  initialSkips,
  packLine,
  packProblem,
  planSummary,
  plural,
} from './packs.js'

const PLAN = {
  problems: [],
  counts: { add: 1, update: 1, same: 1, conflict: 1 },
  items: [
    { kind: 'fields', name: 'customer', label: 'Field', action: 'conflict', why: 'another type' },
    { kind: 'scripts', name: 'CountWords', label: 'Script', action: 'update', diff: '…' },
    { kind: 'lists', name: 'vip_users', label: 'List', action: 'add' },
    { kind: 'dashboards', name: 'Cases', label: 'Dashboard', action: 'same' },
  ],
}

test('the plan of an import: what it says, what starts left out, whether it can be applied', () => {
  assert.equal(planSummary(PLAN.counts), '1 to add, 1 to update, 1 the same, 1 in conflict')
  assert.equal(planSummary({}), 'It holds nothing')
  assert.equal(actionBadge('conflict').color, 'red')
  assert.equal(actionBadge('other').label, 'other')
  // A conflict starts left out, so the rest can be applied at once.
  const skipped = initialSkips(PLAN)
  assert.deepEqual([...skipped], ['fields/customer'])
  assert.deepEqual(importable(PLAN, skipped), { ok: true, why: '', changes: 2 })
  assert.deepEqual(choicesOf(skipped), { 'fields/customer': 'skip' })
  // Put back, it stops everything, and the reason names it.
  const blocked = importable(PLAN, new Set())
  assert.equal(blocked.ok, false)
  assert.match(blocked.why, /Field "customer" conflicts/)
  // What the pack requires and is not there stops it whatever is skipped.
  assert.equal(
    importable({ ...PLAN, problems: ['It requires the pack "base"'] }, skipped).why,
    'It requires the pack "base"',
  )
  const all = new Set(PLAN.items.map((item) => `${item.kind}/${item.name}`))
  assert.equal(importable(PLAN, all).why, 'Everything is left out')
  assert.equal(importable(null, new Set()).ok, false)
})

test('a difference as lines, without its two headers', () => {
  const diff = '--- here\n+++ in the pack\n@@ -1,2 +1,2 @@\n name: x\n-code: old\n+code: new'
  assert.deepEqual(diffLines(diff), [
    { kind: 'hunk', text: '@@ -1,2 +1,2 @@' },
    { kind: 'same', text: ' name: x' },
    { kind: 'del', text: '-code: old' },
    { kind: 'add', text: '+code: new' },
  ])
  assert.deepEqual(diffLines(''), [{ kind: 'same', text: '' }])
})

test('the identity of a pack that is being made', () => {
  assert.equal(idFromName('Acme SOC!'), 'acme-soc')
  assert.equal(idFromName('2026 rules'), 'pack-2026-rules')
  assert.equal(idFromName('???'), '')
  assert.equal(packProblem({ id: 'acme-soc', name: 'Acme SOC', version: '1.0.0' }), null)
  assert.match(packProblem({ id: 'acme-soc', name: ' ', version: '1.0.0' }), /needs a name/)
  assert.match(packProblem({ id: 'Acme', name: 'Acme', version: '1.0.0' }), /lower-case letter/)
  assert.match(packProblem({ id: 'acme', name: 'Acme', version: '1.0' }), /three numbers/)
  assert.match(packProblem({ id: 'acme', name: 'Acme', version: '1.0.0' }, 0), /one item/)
})

test('items by kind, and a pack in a line', () => {
  const groups = byKind(PLAN.items)
  assert.deepEqual(
    groups.map((group) => [group.kind, group.label, group.items.length]),
    [
      ['fields', 'Field', 1],
      ['scripts', 'Script', 1],
      ['lists', 'List', 1],
      ['dashboards', 'Dashboard', 1],
    ],
  )
  assert.equal(plural('Incident type', 2), 'Incident types')
  assert.equal(plural('Field', 1), 'Field')
  assert.equal(
    packLine({ items: [{ there: true }, { there: false }], builtin: true }),
    '2 items · 1 no longer here · part of Nik',
  )
  assert.equal(
    packLine({ items: [{ there: true }], updatedBy: 'admin', updatedAt: '2026-11-19T08:00:00+00:00' }),
    '1 item · installed by admin on 2026-11-19',
  )
})
