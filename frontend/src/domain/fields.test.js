import test from 'node:test'
import assert from 'node:assert/strict'
import {
  addSection,
  byName,
  formatValue,
  fromInput,
  indicatorKind,
  moveField,
  moveSection,
  nameFromLabel,
  nameProblem,
  placeField,
  removeSection,
  setFieldFlags,
  toInput,
  typeOf,
  typePayload,
  unplaceField,
  unplaced,
  updateSection,
  valuesOf,
} from './fields.js'

const FIELDS = [
  { name: 'status', label: 'Status', type: 'choice', system: true, allTypes: true, appliesTo: 'incident' },
  { name: 'severity', label: 'Severity', type: 'choice', system: true, allTypes: true, appliesTo: 'incident' },
  { name: 'campaign', label: 'Campaign', type: 'text', system: false, allTypes: false, appliesTo: 'incident' },
  { name: 'site', label: 'Site', type: 'text', system: false, allTypes: true, appliesTo: 'incident' },
  { name: 'root_cause', label: 'Root cause', type: 'long_text', system: false, allTypes: false, appliesTo: 'incident' },
  { name: 'task_note', label: 'Task note', type: 'text', system: false, allTypes: true, appliesTo: 'task' },
]
const LAYOUT = {
  sections: [
    { id: 'key', title: 'Key facts', key: true, columns: 1, fields: ['status', 'severity'] },
    { id: 'about', title: 'About', key: false, columns: 2, fields: ['campaign'] },
  ],
  tabs: [],
  hidden: [],
}
const TYPE = {
  id: 'bec',
  name: 'BEC',
  fields: [
    { name: 'campaign', required: true, requiredOnClose: false },
    { name: 'root_cause', required: false, requiredOnClose: true },
  ],
  layout: LAYOUT,
  closeReasons: ['Fixed', ' ', 'Not ours'],
}

test('a machine name is made from a label, and checked', () => {
  assert.equal(nameFromLabel('Business unit'), 'business_unit')
  assert.equal(nameFromLabel('  Città / Sede  '), 'citta_sede')
  assert.equal(nameFromLabel('3rd party'), 'f_3rd_party')
  assert.equal(nameFromLabel('!!!'), '')
  assert.equal(nameProblem('business_unit', FIELDS), null)
  assert.equal(nameProblem('campaign', FIELDS), 'There is a field with this name already')
  assert.match(nameProblem('Business Unit', FIELDS), /lower-case letter/)
  assert.match(nameProblem('x', FIELDS), /lower-case letter/)
})

test('a value is shown and typed as its type says', () => {
  const field = (type) => ({ name: 'f', label: 'F', type })
  assert.equal(formatValue(field('bool'), false), 'no')
  assert.equal(formatValue(field('number'), 0), '0')
  assert.equal(formatValue(field('date'), '2026-11-17T09:30:00Z'), '2026-11-17 09:30 UTC')
  assert.equal(formatValue(field('tags'), ['a', 'b']), 'a, b')
  assert.equal(formatValue(field('indicator'), { type: 'domain', value: 'evil.example' }), 'evil.example (domain)')
  assert.equal(formatValue(field('list'), [{ a: 1 }]), '1 row')
  // The status is shown as the list shows it; any other choice as it was written.
  assert.equal(formatValue({ name: 'status', type: 'choice' }, 'in_progress'), 'in progress')
  assert.equal(formatValue(field('choice'), 'needs_review'), 'needs_review')
  assert.equal(formatValue(field('text'), ''), '')
  assert.equal(formatValue(field('text'), undefined), '')

  assert.equal(toInput(field('date'), '2026-11-17T09:30:00Z'), '2026-11-17T09:30')
  assert.equal(toInput(field('bool'), true), 'true')
  assert.equal(toInput(field('tags'), ['a', 'b']), 'a, b')
  assert.deepEqual(toInput(field('list'), null), [])
  assert.equal(toInput(field('text'), null), '')

  assert.equal(fromInput(field('text'), '  hello '), 'hello')
  assert.equal(fromInput(field('text'), '   '), null)
  assert.equal(fromInput(field('number'), '12.5'), 12.5)
  assert.throws(() => fromInput(field('number'), 'many'), /F is a number/)
  assert.equal(fromInput(field('bool'), 'false'), false)
  assert.equal(fromInput(field('date'), '2026-11-17T09:30'), '2026-11-17T09:30:00Z')
  assert.throws(() => fromInput(field('date'), 'yesterday'), /F is a date/)
  assert.deepEqual(fromInput(field('tags'), 'a, b,, a'), ['a', 'b'])
  assert.deepEqual(fromInput(field('multi_choice'), []), null)
  assert.deepEqual(fromInput(field('indicator'), 'evil.example'), { type: 'domain', value: 'evil.example' })
  assert.deepEqual(fromInput(field('json'), '{"a": 1}'), { a: 1 })
  assert.throws(() => fromInput(field('json'), '{a'), /not valid JSON/)
  // What was shown and not touched goes back as it came.
  assert.equal(fromInput(field('date'), toInput(field('date'), '2026-11-17T09:30:00Z')), '2026-11-17T09:30:00Z')
})

test('the kind of an indicator is guessed from what was typed', () => {
  assert.equal(indicatorKind('https://evil.example/x'), 'url')
  assert.equal(indicatorKind('eve@evil.example'), 'email')
  assert.equal(indicatorKind('a'.repeat(64)), 'sha256')
  assert.equal(indicatorKind('a'.repeat(32)), 'md5')
  assert.equal(indicatorKind('185.220.101.47'), 'ip')
  assert.equal(indicatorKind('evil.example'), 'domain')
})

test('an incident has the type it names, and the fields of that type', () => {
  const types = [{ id: 'unclassified', name: 'Unclassified', fields: [] }, TYPE]
  assert.equal(typeOf(types, { type: 'bec' }).name, 'BEC')
  assert.equal(typeOf(types, {}).name, 'Unclassified')
  assert.equal(typeOf(types, { type: 'gone' }).name, 'Unclassified')
  assert.equal(typeOf([], {}), null)
  // What the side list offers: the fields of incidents that are in no section.
  assert.deepEqual(
    unplaced(TYPE, FIELDS).map((field) => field.name),
    ['site', 'root_cause'],
  )
  const values = valuesOf({ id: 'i1', name: 'CEO fraud', assignee: 'anna', fields: { campaign: 'Q4', empty: '' } })
  assert.deepEqual(values, {
    id: 'i1',
    name: 'CEO fraud',
    type: 'unclassified',
    status: 'open',
    owner: 'anna',
    campaign: 'Q4',
  })
})

test('a layout is edited without touching the one it was', () => {
  const frozen = JSON.stringify(LAYOUT)
  const added = addSection(LAYOUT, 'Reach')
  assert.deepEqual(
    added.sections.map((section) => [section.id, section.title]),
    [
      ['key', 'Key facts'],
      ['about', 'About'],
      ['s3', 'Reach'],
    ],
  )
  // A field is in one place: placing it takes it from where it was.
  const placed = placeField(added, 'severity', 's3')
  assert.deepEqual(placed.sections[0].fields, ['status'])
  assert.deepEqual(placed.sections[2].fields, ['severity'])
  assert.deepEqual(placeField(LAYOUT, 'site', 'key', 0).sections[0].fields, ['site', 'status', 'severity'])
  assert.equal(placeField(LAYOUT, 'site', 'nope'), LAYOUT)
  assert.deepEqual(unplaceField(LAYOUT, 'campaign').sections[1].fields, [])

  // Up and down; past the edge of a section, into the next one.
  assert.deepEqual(moveField(LAYOUT, 'severity', -1).sections[0].fields, ['severity', 'status'])
  const down = moveField(LAYOUT, 'severity', 1)
  assert.deepEqual(down.sections[0].fields, ['status'])
  assert.deepEqual(down.sections[1].fields, ['severity', 'campaign'])
  assert.deepEqual(moveField(LAYOUT, 'campaign', -1).sections[0].fields, ['status', 'severity', 'campaign'])
  assert.equal(moveField(LAYOUT, 'status', -1), LAYOUT)
  assert.equal(moveField(LAYOUT, 'nope', 1), LAYOUT)

  assert.deepEqual(
    moveSection(LAYOUT, 'about', -1).sections.map((section) => section.id),
    ['about', 'key'],
  )
  assert.equal(moveSection(LAYOUT, 'key', -1), LAYOUT)
  assert.deepEqual(
    removeSection(LAYOUT, 'about').sections.map((section) => section.id),
    ['key'],
  )
  // One side panel at most.
  const panel = updateSection(LAYOUT, 'about', { key: true, title: 'Panel' })
  assert.deepEqual(
    panel.sections.map((section) => [section.title, section.key]),
    [
      ['Key facts', false],
      ['Panel', true],
    ],
  )
  assert.equal(JSON.stringify(LAYOUT), frozen)
})

test('the flags of a field of a type, and what is saved of the type', () => {
  assert.deepEqual(setFieldFlags(TYPE.fields, 'campaign', { requiredOnClose: true })[0], {
    name: 'campaign',
    required: true,
    requiredOnClose: true,
  })
  assert.deepEqual(setFieldFlags(TYPE.fields, 'site', {})[2], { name: 'site', required: false, requiredOnClose: false })
  const payload = typePayload({ ...TYPE, name: ' BEC ' })
  assert.equal(payload.name, 'BEC')
  assert.deepEqual(payload.closeReasons, ['Fixed', 'Not ours'])
  assert.equal(payload.colour, 'slate')
  assert.deepEqual(payload.layout, LAYOUT)
  // What names a section that was taken away is not sent: the server would refuse it.
  const trimmed = typePayload({
    ...TYPE,
    layout: {
      ...LAYOUT,
      grid: [{ id: 'a', kind: 'section', section: 'gone', x: 0, y: 0, w: 6, h: 3 }],
      close: { sections: ['about', 'gone'] },
      quick: [{ kind: 'section', section: 'gone' }, { kind: 'stats' }],
    },
  }).layout
  assert.deepEqual(trimmed.grid, [])
  assert.deepEqual(trimmed.close, { sections: ['about'] })
  assert.deepEqual(trimmed.quick, [{ kind: 'stats' }])
})

test('the page of an incident follows the layout of its type', async () => {
  const { changesOf, orderTabs, panelSection, summarySections } = await import('./fields.js')
  const tabs = ['summary', 'timeline', 'iocs', 'mail', 'malware'].map((id) => ({ id }))
  const ids = (layout) => orderTabs(tabs, layout).map((tab) => tab.id)
  assert.deepEqual(ids(null), ['summary', 'timeline', 'iocs', 'mail', 'malware'])
  assert.deepEqual(ids({ tabs: ['mail', 'summary'], hidden: ['malware'] }), ['mail', 'summary', 'timeline', 'iocs'])
  // A tab that does not exist is ignored, and the Summary is never hidden.
  assert.deepEqual(ids({ tabs: ['war_room'], hidden: ['summary', 'timeline'] }), ['summary', 'iocs', 'mail', 'malware'])

  assert.equal(panelSection(TYPE).id, 'key')
  assert.equal(panelSection({ layout: { sections: [{ id: 'a', key: false, fields: [] }] } }), null)
  // The Summary shows the other sections, without what its own form edits and without what is gone.
  const type = {
    ...TYPE,
    layout: {
      sections: [
        ...LAYOUT.sections,
        { id: 'more', title: 'More', key: false, fields: ['status', 'site', 'gone'] },
        { id: 'empty', title: 'Empty', key: false, fields: ['severity'] },
      ],
    },
  }
  assert.deepEqual(
    summarySections(type, FIELDS).map((section) => [section.id, section.fields]),
    [
      ['about', ['campaign']],
      ['more', ['site']],
    ],
  )

  // A form sends what changed; an emptied field is null; a required one cannot be emptied.
  const known = byName(FIELDS)
  const form = [known.campaign, known.site, known.root_cause]
  const values = { campaign: 'Q4', site: 'Milan' }
  assert.deepEqual(changesOf(TYPE, form, { campaign: 'Q4', site: '', root_cause: 'A rule' }, values), {
    site: null,
    root_cause: 'A rule',
  })
  assert.deepEqual(changesOf(TYPE, form, { campaign: 'Q4', site: 'Milan', root_cause: '' }, values), {})
  assert.throws(() => changesOf(TYPE, form, { campaign: ' ', site: 'Milan' }, values), /Campaign is required/)
})
