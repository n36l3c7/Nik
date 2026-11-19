import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  QUICK_KINDS,
  QUICK_MAX,
  blockTitle,
  countFigures,
  defaultBlocks,
  lastLines,
  nearestTimer,
  quickBlocks,
} from './quickView.js'

const LAYOUT = {
  sections: [
    { id: 'key', title: 'Key facts', key: true, columns: 1, fields: ['status', 'severity'] },
    { id: 'sender', title: 'Sender', key: false, columns: 2, fields: ['mail_from', 'mail_subject'] },
    { id: 'more', title: 'More', key: false, columns: 1, fields: ['impact'] },
  ],
}
const type = (quick) => ({ id: 'phishing', layout: quick === undefined ? LAYOUT : { ...LAYOUT, quick } })
const kinds = (blocks) => blocks.map((block) => [block.kind, block.section ?? block.text ?? null])

test('a type that arranged no quick view shows the details, its first section, the numbers and the last lines', () => {
  const expected = [
    ['facts', null],
    ['section', 'sender'],
    ['stats', null],
    ['last', null],
  ]
  assert.deepEqual(kinds(defaultBlocks(type())), expected)
  assert.deepEqual(kinds(quickBlocks(type())), expected)
  assert.deepEqual(kinds(quickBlocks(type([]))), expected)
  // The side panel is never the first section; a type with no section, or no type at all, has none to show.
  const bare = [
    ['facts', null],
    ['stats', null],
    ['last', null],
  ]
  assert.deepEqual(kinds(quickBlocks({ layout: { sections: [LAYOUT.sections[0]] } })), bare)
  assert.deepEqual(kinds(quickBlocks(null)), bare)
  assert.deepEqual(kinds(quickBlocks({ layout: { quick: 'facts' } })), bare)
})

test('the blocks a type keeps are drawn in its order, each with an id of its own', () => {
  const blocks = quickBlocks(
    type([
      { kind: 'note', text: 'Call the owner of the mailbox first.' },
      { kind: 'section', section: 'more' },
      { kind: 'timers' },
      { kind: 'facts' },
      { kind: 'linked' },
      { kind: 'note', text: 'Then block the sender.' },
    ]),
  )
  assert.deepEqual(kinds(blocks), [
    ['note', 'Call the owner of the mailbox first.'],
    ['section', 'more'],
    ['timers', null],
    ['facts', null],
    ['linked', null],
    ['note', 'Then block the sender.'],
  ])
  assert.equal(new Set(blocks.map((block) => block.id)).size, blocks.length)
})

test('what cannot be drawn is left out, and never throws', () => {
  const blocks = quickBlocks(
    type([
      null,
      'facts',
      { kind: 'playbooks' },
      { kind: 'section', section: 'key' }, // the side panel is not a section of the page
      { kind: 'section', section: 'gone' },
      { kind: 'section', section: 'sender' },
      { kind: 'section', section: 'sender' },
      { kind: 'stats' },
      { kind: 'stats' },
      { kind: 'note', text: '   ' },
      { kind: 'note' },
    ]),
  )
  assert.deepEqual(kinds(blocks), [
    ['section', 'sender'],
    ['stats', null],
  ])
  // Nothing left: the default ones, not an empty panel.
  assert.deepEqual(kinds(quickBlocks(type([{ kind: 'section', section: 'gone' }])))[0], ['facts', null])
  // Twelve at most, and a text no longer than a text of the Summary.
  const many = quickBlocks(type(Array.from({ length: 20 }, (_, index) => ({ kind: 'note', text: `note ${index}` }))))
  assert.equal(many.length, QUICK_MAX)
  assert.equal(quickBlocks(type([{ kind: 'note', text: 'x'.repeat(5000) }]))[0].text.length, 2000)
})

test('a block is called by its kind, a section by its title, a text by nothing', () => {
  assert.equal(blockTitle({ kind: 'facts' }, LAYOUT), 'Details')
  assert.equal(blockTitle({ kind: 'section', section: 'sender' }, LAYOUT), 'Sender')
  assert.equal(blockTitle({ kind: 'section', section: 'gone' }, LAYOUT), 'Section')
  assert.equal(blockTitle({ kind: 'last' }, LAYOUT), 'Last in the War Room')
  assert.equal(blockTitle({ kind: 'note', text: 'x' }, LAYOUT), '')
  assert.equal(blockTitle(null, null), '')
  assert.deepEqual(
    QUICK_KINDS.map((kind) => kind.id),
    ['facts', 'section', 'stats', 'timers', 'last', 'linked', 'note'],
  )
})

test('the header shows the timer nearest to its time, and the one that is over before any other', () => {
  const timer = (label, state, dueS, elapsedS, breached = false) => ({
    label,
    state,
    dueS,
    elapsedS,
    remainingS: dueS ? dueS - elapsedS : null,
    breached,
  })
  assert.equal(nearestTimer([]), null)
  assert.equal(nearestTimer(null), null)
  // Stopped, paused, or running against no time: nothing to be near to.
  assert.equal(
    nearestTimer([
      timer('A', 'stopped', 600, 700, true),
      timer('B', 'paused', 600, 10),
      timer('C', 'running', null, 5),
    ]),
    null,
  )
  assert.deepEqual(nearestTimer([timer('Close', 'running', 86400, 3600), timer('Contain', 'running', 7200, 2880)]), {
    label: 'Contain',
    text: 'SLA 1 h 12 min left',
    late: false,
  })
  assert.deepEqual(
    nearestTimer([timer('Close', 'running', 86400, 3600), timer('Assign', 'running', 600, 1500, true)]),
    {
      label: 'Assign',
      text: 'SLA 15 min over',
      late: true,
    },
  )
})

test('the numbers of the evidence are those of the Summary, zero for what is missing', () => {
  assert.deepEqual(countFigures({ browserEvents: 5, commands: 3, endpointArtifacts: 4, flagged: 2, notes: 1 }), [
    ['Browser events', 5],
    ['Commands', 3],
    ['Endpoint artifacts', 4],
    ['Flagged', 2],
    ['Bookmarks', 0],
    ['Notes', 1],
  ])
  assert.ok(countFigures(undefined).every(([, value]) => value === 0))
})

test('the last lines of the War Room come newest first, said in a line each', () => {
  const entries = [
    { id: 'e1', at: '2026-11-19T09:30:00Z', author: 'admin', kind: 'note', body: { text: 'old' } },
    {
      id: 'e2',
      at: '2026-11-19T09:41:00Z',
      author: 'nik-automation',
      kind: 'result',
      body: { title: 'Triage finished', playbook: 'phishing-triage' },
    },
    { id: 'e3', at: '2026-11-19T09:52:00Z', author: 'n36', kind: 'note', body: { text: 'sender blocked' } },
    { id: 'e4', at: '2026-11-19T09:55:00Z', author: 'n36', kind: 'command', body: { line: '!ip 1.2.3.4' } },
  ]
  assert.deepEqual(lastLines(entries), [
    { id: 'e4', at: '2026-11-19T09:55:00Z', who: 'n36', text: '!ip 1.2.3.4', tone: 'command' },
    { id: 'e3', at: '2026-11-19T09:52:00Z', who: 'n36', text: 'sender blocked', tone: 'note' },
    {
      id: 'e2',
      at: '2026-11-19T09:41:00Z',
      who: 'automation',
      text: 'Triage finished: playbook phishing-triage',
      tone: 'ok',
    },
  ])
  assert.deepEqual(lastLines(null), [])
})
