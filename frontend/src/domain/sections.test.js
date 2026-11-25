import assert from 'node:assert/strict'
import { test } from 'node:test'
import { RAIL_SECTIONS, homeMove } from './sections.js'

test('the rail, from the top', () => {
  assert.deepEqual(
    RAIL_SECTIONS.map((section) => section.label),
    ['Dashboards', 'Incidents', 'My tasks', 'Artifacts', 'Indicators', 'Automations', 'Playground'],
  )
})

test('an entry goes to the first screen of its section from another section', () => {
  const at = { path: '/incident/i1', panel: null, incidentId: 'i1' }
  assert.deepEqual(homeMove('dashboards', at), { path: '/dashboards' })
  assert.deepEqual(homeMove('tasks', at), { path: '/tasks' })
  assert.deepEqual(homeMove('incidents', at), { path: '/incidents', panel: null })
  assert.deepEqual(homeMove('iocs', at), { path: '/iocs', panel: 'iocs' })
  assert.deepEqual(homeMove('automation', at), { path: '/automation/playbooks' })
  assert.deepEqual(homeMove('playground', at), { path: '/playground' })
  assert.deepEqual(homeMove('settings', at), { path: '/settings/analysis/business-hours' })
})

test('…and from a screen inside the section', () => {
  assert.deepEqual(homeMove('automation', { path: '/automation/playbooks/p1' }), { path: '/automation/playbooks' })
  assert.deepEqual(homeMove('automation', { path: '/automation/playbooks/p1/branches/b' }), {
    path: '/automation/playbooks',
  })
  assert.deepEqual(homeMove('automation', { path: '/automation/runs/r1' }), { path: '/automation/playbooks' })
  assert.deepEqual(homeMove('automation', { path: '/automation/scripts/s1' }), { path: '/automation/playbooks' })
  assert.deepEqual(homeMove('settings', { path: '/settings/platform/sla' }), {
    path: '/settings/analysis/business-hours',
  })
  assert.deepEqual(homeMove('incidents', { path: '/incident/i1', incidentId: 'i1' }), {
    path: '/incidents',
    panel: null,
  })
  assert.deepEqual(homeMove('iocs', { path: '/iocs/lists/7', panel: 'iocs' }), { path: '/iocs', panel: 'iocs' })
  // A dashboard that is not the first one, or that is being edited; a task that is not the first.
  assert.deepEqual(homeMove('dashboards', { path: '/dashboards/d2', first: { dashboards: false } }), {
    path: '/dashboards',
  })
  assert.deepEqual(homeMove('tasks', { path: '/tasks/t9', first: { tasks: false } }), { path: '/tasks' })
  // The address is the first one already and the page is not as first opened: it starts again where it is.
  assert.deepEqual(homeMove('dashboards', { path: '/dashboards', first: { dashboards: false } }), { path: null })
})

test('pressed on the first screen of its section an entry does nothing', () => {
  assert.equal(homeMove('dashboards', { path: '/dashboards/d1', first: { dashboards: true } }), null)
  assert.equal(homeMove('tasks', { path: '/tasks/t1', first: { tasks: true } }), null)
  assert.equal(homeMove('incidents', { path: '/incidents', panel: null }), null)
  assert.equal(homeMove('incidents', { path: '/', panel: null }), null)
  assert.equal(homeMove('iocs', { path: '/iocs', panel: 'iocs', quick: 'all' }), null)
  assert.equal(homeMove('automation', { path: '/automation/playbooks' }), null)
  assert.equal(homeMove('playground', { path: '/playground' }), null)
  assert.equal(homeMove('settings', { path: '/settings/analysis/business-hours' }), null)
  assert.equal(homeMove('artifacts', { path: '/artifacts', panel: 'artifacts' }), null)
  assert.equal(homeMove('artifacts', { path: '/artifacts', panel: null }), null)
  assert.equal(homeMove('nothing', { path: '/' }), null)
})

test('the artifacts: their page, with the list at the side, no artifact open and nothing filtered', () => {
  // From an open artifact, from an incident, from a page drawn over it: the page of the artifacts.
  for (const at of [
    { path: '/artifact/a1', panel: 'artifacts', incidentId: 'i1' },
    { path: '/incident/i1', panel: null, incidentId: 'i1' },
    { path: '/settings/platform/sla', incidentId: 'i1' },
    { path: '/iocs', panel: 'iocs' },
  ]) {
    assert.deepEqual(homeMove('artifacts', at), { path: '/artifacts', panel: 'artifacts' })
  }
  // There already, with a filter that narrows the list: it is taken off, and the address stays.
  assert.deepEqual(homeMove('artifacts', { path: '/artifacts', panel: 'artifacts', filtered: true }), {
    path: null,
    panel: 'artifacts',
  })
})

test('the indicators: the page on every indicator, with its panel', () => {
  assert.deepEqual(homeMove('iocs', { path: '/iocs', panel: null }), { path: null, panel: 'iocs' })
  assert.deepEqual(homeMove('iocs', { path: '/iocs', panel: 'iocs', quick: 'malicious' }), {
    path: null,
    panel: 'iocs',
  })
})

test('the incidents: the list alone', () => {
  assert.deepEqual(homeMove('incidents', { path: '/incidents', panel: 'artifacts' }), { path: null, panel: null })
  assert.deepEqual(homeMove('incidents', { path: '/iocs', panel: 'iocs' }), { path: '/incidents', panel: null })
})
