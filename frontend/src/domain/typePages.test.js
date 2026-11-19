import assert from 'node:assert/strict'
import { test } from 'node:test'
import { orderTabs } from './fields.js'
import {
  PAGES_MAX,
  addPage,
  addQuick,
  canAddPage,
  canAddQuick,
  closeFields,
  closeSections,
  closeTag,
  layoutForSaving,
  moveCloseSection,
  moveQuick,
  moveTab,
  newPageId,
  openTasksText,
  pageIdOf,
  pageName,
  pageOf,
  pageTabId,
  pagesOf,
  placeTab,
  quickFreeSections,
  quickList,
  quickTag,
  removePage,
  removeQuick,
  renamePage,
  setPageGrid,
  tabRows,
  tabTag,
  toggleCloseSection,
  toggleTab,
  updateQuick,
} from './typePages.js'

const BAR = [
  { id: 'summary', label: 'Summary' },
  { id: 'war_room', label: 'War Room' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'evidence', label: 'Evidence' },
]
const LAYOUT = {
  sections: [
    { id: 'key', title: 'Key facts', key: true, columns: 1, fields: ['status', 'severity'] },
    { id: 'outcome', title: 'Outcome', key: false, columns: 2, fields: ['mailboxes', 'status', 'time_to_close'] },
    { id: 'lessons', title: 'Lessons', key: false, columns: 1, fields: ['what_to_change'] },
  ],
  tabs: [],
  hidden: [],
}
const ids = (rows) => rows.map((row) => row.id)

test('a page of a type is a tab named page:<id>', () => {
  assert.equal(pageTabId('containment'), 'page:containment')
  assert.equal(pageIdOf('page:containment'), 'containment')
  assert.equal(pageIdOf('summary'), null)
  assert.equal(pageIdOf(null), null)
  const layout = {
    ...LAYOUT,
    pages: [
      { id: 'containment', name: 'Containment ', grid: [{ kind: 'note', x: 0, y: 0, w: 4, h: 2, text: 'First' }] },
      { id: 'Bad Id', name: 'dropped' },
      { id: 'containment', name: 'twice' },
      { id: 'empty', name: '' },
      null,
    ],
  }
  const pages = pagesOf(layout)
  assert.deepEqual(ids(pages), ['containment', 'empty'])
  // The name is kept as it was typed, so that it can be typed; the tab is called by it, trimmed.
  assert.equal(pages[0].name, 'Containment ')
  assert.equal(pageName(pages[0]), 'Containment')
  assert.equal(pageName(pages[1]), 'Page')
  assert.equal(pages[0].grid[0].kind, 'note')
  assert.deepEqual(pages[1].grid, [])
  assert.equal(pageOf(layout, 'containment').id, 'containment')
  assert.equal(pageOf(layout, 'gone'), null)
  assert.deepEqual(pagesOf(null), [])
})

test('the tabs of the bar are listed in the order the incident page draws them', () => {
  const { layout } = addPage(LAYOUT, 'Containment')
  // A page that was placed nowhere comes after the tabs of Nik.
  assert.deepEqual(ids(tabRows(layout, BAR)), ['summary', 'war_room', 'timeline', 'evidence', 'page:containment'])
  assert.deepEqual(
    tabRows(layout, BAR).map((row) => tabTag(row)),
    ['page', 'Nik', 'Nik', 'Nik', 'page · yours'],
  )
  // Moved up twice, it is before the Timeline; the order names every tab of the bar from then on.
  let moved = moveTab(moveTab(layout, BAR, 'page:containment', -1), BAR, 'page:containment', -1)
  assert.deepEqual(moved.tabs, ['summary', 'war_room', 'page:containment', 'timeline', 'evidence'])
  assert.equal(moveTab(moved, BAR, 'summary', -1), moved)
  assert.equal(moveTab(moved, BAR, 'evidence', 1), moved)
  assert.equal(moveTab(moved, BAR, 'gone', 1), moved)
  // Dropped on the Summary, it takes its place.
  moved = placeTab(moved, BAR, 'page:containment', 'summary')
  assert.deepEqual(moved.tabs, ['page:containment', 'summary', 'war_room', 'timeline', 'evidence'])
  assert.equal(placeTab(moved, BAR, 'summary', 'summary'), moved)
  // Hidden, a tab keeps its place in the list and says so; the Summary is never hidden.
  const hidden = toggleTab(toggleTab(moved, 'timeline'), 'summary')
  assert.deepEqual(hidden.hidden, ['timeline'])
  assert.equal(tabTag(tabRows(hidden, BAR).find((row) => row.id === 'timeline')), 'Nik · hidden')
  assert.deepEqual(toggleTab(hidden, 'timeline').hidden, [])
  // What the layout says of the kinds of evidence is kept when the bar is ordered.
  const kinds = moveTab({ ...LAYOUT, tabs: ['mail', 'timeline', 'malware'] }, BAR, 'timeline', 1)
  assert.deepEqual(kinds.tabs, ['summary', 'timeline', 'war_room', 'evidence', 'mail', 'malware'])

  // The incident page orders the same tabs the same way, without the hidden ones.
  const page = pageOf(hidden, 'containment')
  const bar = orderTabs([...BAR, { id: pageTabId(page.id), label: pageName(page) }], hidden)
  assert.deepEqual(ids(bar), ids(tabRows(hidden, BAR).filter((row) => !row.hidden)))
  assert.deepEqual(ids(bar), ['page:containment', 'summary', 'war_room', 'evidence'])
})

test('a page is added, renamed, arranged and deleted', () => {
  assert.equal(newPageId([], 'Containment plan'), 'containment-plan')
  assert.equal(newPageId([{ id: 'containment-plan' }], 'Containment plan'), 'containment-plan-2')
  assert.equal(newPageId([], '2nd line'), 'page-2nd-line')
  assert.equal(newPageId([], '!!!'), 'page')
  const first = addPage(LAYOUT, '  Containment  ')
  assert.equal(first.id, 'containment')
  assert.deepEqual(first.layout.pages, [{ id: 'containment', name: 'Containment', grid: [] }])
  assert.equal(LAYOUT.pages, undefined)
  // A page needs a name; a type has ten at most.
  assert.deepEqual(addPage(LAYOUT, '  '), { layout: LAYOUT, id: null })
  let full = LAYOUT
  for (let index = 0; index < PAGES_MAX; index += 1) full = addPage(full, `Page ${index}`).layout
  assert.equal(canAddPage(full), false)
  assert.equal(addPage(full, 'One more').id, null)
  assert.equal(canAddPage(LAYOUT), true)

  const renamed = renamePage(first.layout, 'containment', 'Containment and recovery')
  assert.equal(pageOf(renamed, 'containment').name, 'Containment and recovery')
  const grid = [{ id: 'facts', kind: 'facts', x: 0, y: 0, w: 7, h: 3 }]
  const arranged = setPageGrid(renamed, 'containment', grid)
  assert.deepEqual(pageOf(arranged, 'containment').grid, grid)
  // Deleted, it leaves the tabs with it.
  const placed = toggleTab(moveTab(arranged, BAR, 'page:containment', -1), 'page:containment')
  const removed = removePage(placed, 'containment')
  assert.deepEqual(removed.pages, [])
  assert.ok(!removed.tabs.includes('page:containment') && !removed.hidden.includes('page:containment'))
})

test('the close form shows sections of the type, in the order chosen', () => {
  assert.deepEqual(closeSections(LAYOUT), [])
  assert.equal(closeTag(LAYOUT), 'as it always was')
  let layout = toggleCloseSection(toggleCloseSection(LAYOUT, 'lessons'), 'outcome')
  assert.deepEqual(layout.close, { sections: ['lessons', 'outcome'] })
  assert.equal(closeTag(layout), '2 sections')
  layout = moveCloseSection(layout, 'outcome', -1)
  assert.deepEqual(ids(closeSections(layout)), ['outcome', 'lessons'])
  assert.equal(moveCloseSection(layout, 'outcome', -1), layout)
  // A section that was taken away is not in the form; taking the last one out leaves no form.
  assert.deepEqual(ids(closeSections({ ...LAYOUT, close: { sections: ['gone', 'lessons', 'lessons'] } })), ['lessons'])
  const emptied = toggleCloseSection(toggleCloseSection(layout, 'outcome'), 'lessons')
  assert.equal('close' in emptied, false)
  assert.equal(closeTag(toggleCloseSection(LAYOUT, 'lessons')), '1 section')

  // The fields of a section the form edits: what can be written, without what closing itself sets.
  const known = {
    mailboxes: { name: 'mailboxes', label: 'Mailboxes reached', type: 'number' },
    status: { name: 'status', label: 'Status', type: 'choice' },
    time_to_close: { name: 'time_to_close', label: 'Time to close', type: 'timer', writable: false },
    what_to_change: { name: 'what_to_change', label: 'What to change', type: 'long_text' },
  }
  const flags = [{ name: 'mailboxes', requiredOnClose: true }, { name: 'what_to_change' }]
  assert.deepEqual(
    closeFields(LAYOUT.sections[1], known, flags).map((item) => [item.field.name, item.needed]),
    [['mailboxes', true]],
  )
  assert.deepEqual(
    closeFields(LAYOUT.sections[2], known, flags).map((item) => [item.field.name, item.needed]),
    [['what_to_change', false]],
  )
  assert.deepEqual(closeFields(null, known, flags), [])
  assert.equal(openTasksText(0), '')
  assert.equal(openTasksText(1), '1 task of the work plan is still open.')
  assert.equal(openTasksText(2), '2 tasks of the work plan are still open.')
})

test('the quick view is a list of blocks, edited in order', () => {
  assert.deepEqual(quickList(LAYOUT), [])
  assert.equal(quickTag(LAYOUT), 'generated')
  let layout = addQuick(LAYOUT, 'facts')
  layout = addQuick(layout, 'section')
  layout = addQuick(layout, 'note')
  layout = addQuick(layout, 'section', 'lessons')
  assert.deepEqual(layout.quick, [
    { kind: 'facts' },
    { kind: 'section', section: 'outcome' },
    { kind: 'note', text: '' },
    { kind: 'section', section: 'lessons' },
  ])
  assert.equal(quickTag(layout), '4 blocks')
  // Once is once: the details are there, every section of the page has its block (the side panel is none).
  assert.equal(canAddQuick(layout, 'facts'), false)
  assert.equal(addQuick(layout, 'facts'), layout)
  assert.equal(canAddQuick(layout, 'section'), false)
  assert.deepEqual(quickFreeSections(layout), [])
  assert.equal(canAddQuick(layout, 'note'), true)
  assert.equal(canAddQuick(layout, 'unicorn'), false)
  layout = updateQuick(layout, 2, { text: 'Call the owner.' })
  assert.equal(layout.quick[2].text, 'Call the owner.')
  layout = moveQuick(layout, 2, -2)
  assert.deepEqual(
    layout.quick.map((block) => block.kind),
    ['note', 'facts', 'section', 'section'],
  )
  assert.equal(moveQuick(layout, 0, -1), layout)
  layout = removeQuick(layout, 1)
  assert.deepEqual(
    layout.quick.map((block) => block.kind),
    ['note', 'section', 'section'],
  )
  // What cannot be drawn is not in the list; the last block removed leaves the generated view.
  assert.deepEqual(
    quickList({
      ...LAYOUT,
      quick: [{ kind: 'section', section: 'key' }, { kind: 'unicorn' }, { kind: 'stats' }, { kind: 'stats' }, null],
    }),
    [{ kind: 'stats' }],
  )
  assert.equal('quick' in removeQuick(addQuick(LAYOUT, 'stats'), 0), false)
  let many = LAYOUT
  for (let index = 0; index < 20; index += 1) many = addQuick(many, 'note')
  assert.equal(many.quick.length, 12)
})

test('a layout is saved without what names something that is gone', () => {
  const layout = {
    ...LAYOUT,
    tabs: ['summary', 'page:containment', 'page:gone', 'mail'],
    hidden: ['page:gone', 'timeline'],
    grid: [
      { id: 'a', kind: 'section', section: 'gone', x: 0, y: 0, w: 6, h: 3 },
      { id: 'b', kind: 'facts', x: 0, y: 3, w: 6, h: 3 },
    ],
    pages: [
      {
        id: 'containment',
        name: '  Containment ',
        grid: [
          { id: 'a', kind: 'section', section: 'gone', x: 0, y: 0, w: 6, h: 3 },
          { id: 'b', kind: 'linked', x: 0, y: 3, w: 6, h: 3 },
        ],
      },
      { id: 'nameless', name: ' ' },
    ],
    close: { sections: ['gone', 'lessons'] },
    quick: [{ kind: 'note', text: '  ' }, { kind: 'section', section: 'gone' }, { kind: 'last' }],
  }
  assert.deepEqual(layoutForSaving(layout), {
    sections: LAYOUT.sections,
    tabs: ['summary', 'page:containment', 'mail'],
    hidden: ['timeline'],
    grid: [{ id: 'b', kind: 'facts', x: 0, y: 3, w: 6, h: 3 }],
    pages: [
      { id: 'containment', name: 'Containment', grid: [{ id: 'b', kind: 'linked', x: 0, y: 3, w: 6, h: 3 }] },
      { id: 'nameless', name: 'Page', grid: [] },
    ],
    close: { sections: ['lessons'] },
    quick: [{ kind: 'last' }],
  })
  // A layout that has none of it is sent as it is.
  assert.deepEqual(layoutForSaving(LAYOUT), LAYOUT)
  assert.equal(layoutForSaving(null), null)
})
