import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  GRID_MAX,
  WIDGET_KINDS,
  addWidget,
  canAdd,
  cleanGrid,
  defaultGrid,
  freeSections,
  gridOf,
  sectionHeight,
  widgetTitle,
} from './layoutGrid.js'

const LAYOUT = {
  sections: [
    { id: 'key', title: 'Key facts', key: true, columns: 1, fields: ['status', 'severity'] },
    { id: 'about', title: 'What it is about', key: false, columns: 2, fields: ['host', 'username', 'os', 'category'] },
    { id: 'more', title: 'More', key: false, columns: 1, fields: ['impact'] },
  ],
  tabs: [],
  hidden: [],
}

test('a type that arranged no page gets what the Summary showed, in the same order', () => {
  const grid = defaultGrid(LAYOUT)
  assert.deepEqual(
    grid.map((widget) => [widget.kind, widget.section ?? null, widget.x, widget.y, widget.w]),
    [
      ['facts', null, 0, 0, 7],
      ['stats', null, 7, 0, 5],
      ['section', 'about', 0, 3, 12],
      ['section', 'more', 0, 3 + sectionHeight(LAYOUT.sections[1]), 12],
      ['timeline', null, 0, 3 + sectionHeight(LAYOUT.sections[1]) + sectionHeight(LAYOUT.sections[2]), 12],
    ],
  )
  // The side panel's section is not on the page; nothing overlaps.
  assert.ok(!grid.some((widget) => widget.section === 'key'))
  // No layout at all: the details, the numbers, the flags and notes.
  assert.deepEqual(
    defaultGrid(null).map((widget) => widget.kind),
    ['facts', 'stats', 'timeline'],
  )
  assert.deepEqual(gridOf({ layout: LAYOUT }), { grid, custom: false })
  assert.equal(gridOf(null).custom, false)
  // A section is as tall as its fields ask, within the limits of a widget.
  assert.equal(sectionHeight({ fields: [], columns: 1 }), 2)
  assert.equal(sectionHeight({ fields: ['a', 'b', 'c', 'd'], columns: 2 }), 2)
  assert.equal(sectionHeight({ fields: ['a', 'b', 'c', 'd'], columns: 1 }), 3)
  // What the details already show does not make a section taller.
  assert.equal(sectionHeight({ fields: ['host', 'username', 'os', 'status', 'a'], columns: 1 }), 2)
  assert.equal(sectionHeight({ fields: Array.from({ length: 80 }, (_, index) => `f${index}`), columns: 1 }), 12)
})

test('a kept grid is drawn as it is, without what cannot be drawn', () => {
  const kept = [
    { id: 'a', kind: 'war_room', x: 0, y: 0, w: 6, h: 6 },
    { id: 'b', kind: 'section', section: 'about', x: 6, y: 0, w: 6, h: 3, title: '  Where  ' },
    { id: 'c', kind: 'section', section: 'gone', x: 0, y: 6, w: 6, h: 3 },
    { id: 'd', kind: 'unicorn', x: 0, y: 9, w: 6, h: 3 },
    { id: 'e', kind: 'war_room', x: 0, y: 12, w: 6, h: 6 },
    { id: 'f', kind: 'section', section: 'key', x: 0, y: 6, w: 6, h: 3 },
    { id: 'a', kind: 'note', x: 40, y: -3, w: 99, h: 99, text: 'Call the owner first' },
    { id: 'g', kind: 'playbooks', x: 'x', y: 2.4, playbooks: ['p1', 'p1', '', 'p2'] },
    null,
  ]
  const { grid, custom } = gridOf({ layout: { ...LAYOUT, grid: kept } })
  assert.equal(custom, true)
  assert.deepEqual(grid, [
    { id: 'a', kind: 'war_room', x: 0, y: 0, w: 6, h: 6 },
    { id: 'b', kind: 'section', section: 'about', x: 6, y: 0, w: 6, h: 3, title: 'Where' },
    // Out of the columns, taller than a widget may be, an id used twice: put right.
    { id: 'a-3', kind: 'note', x: 0, y: 0, w: 12, h: 12, text: 'Call the owner first' },
    { id: 'g', kind: 'playbooks', x: 0, y: 2, w: 4, h: 2, playbooks: ['p1', 'p2'] },
  ])
  // A grid left with nothing is not a page: the type gets the generated one.
  assert.equal(gridOf({ layout: { ...LAYOUT, grid: [{ kind: 'unicorn' }] } }).custom, false)
  assert.equal(
    cleanGrid(
      Array.from({ length: 80 }, () => ({ kind: 'note' })),
      LAYOUT,
    ).length,
    GRID_MAX,
  )
  assert.deepEqual(cleanGrid('nonsense', LAYOUT), [])
})

test('a widget is called by its title, its section or its kind', () => {
  assert.equal(widgetTitle({ kind: 'section', section: 'about' }, LAYOUT), 'What it is about')
  assert.equal(widgetTitle({ kind: 'section', section: 'about', title: 'Where' }, LAYOUT), 'Where')
  assert.equal(widgetTitle({ kind: 'section', section: 'gone' }, LAYOUT), 'Section')
  assert.equal(widgetTitle({ kind: 'war_room' }, LAYOUT), 'War Room')
  assert.equal(widgetTitle({ kind: 'unicorn' }, LAYOUT), 'Widget')
})

test('a widget is added under the others; some kinds are there once', () => {
  const grid = defaultGrid(LAYOUT)
  const bottom = grid.reduce((rows, widget) => Math.max(rows, widget.y + widget.h), 0)
  assert.equal(canAdd(grid, 'facts'), false)
  assert.equal(addWidget(grid, 'facts'), grid)
  assert.equal(canAdd(grid, 'unicorn'), false)
  const noted = addWidget(grid, 'note')
  assert.deepEqual(noted.at(-1), { id: `note-${grid.length + 1}`, kind: 'note', x: 0, y: bottom, w: 4, h: 2, text: '' })
  // A second text is allowed, with an id of its own.
  const twice = addWidget(noted, 'note')
  assert.equal(new Set(twice.map((widget) => widget.id)).size, twice.length)
  // A section widget is offered for the sections that have none.
  assert.deepEqual(freeSections(grid, LAYOUT), [])
  assert.deepEqual(
    freeSections(
      grid.filter((widget) => widget.section !== 'more'),
      LAYOUT,
    ).map((section) => section.id),
    ['more'],
  )
  const again = addWidget(
    grid.filter((widget) => widget.section !== 'more'),
    'section',
    { section: 'more' },
  )
  assert.equal(again.at(-1).section, 'more')
  // Every kind says what it is and how large it starts.
  for (const kind of WIDGET_KINDS)
    assert.ok(kind.label && kind.hint && kind.w >= 1 && kind.w <= 12 && kind.h >= 1, kind.id)
  const full = Array.from({ length: GRID_MAX }, (_, index) => ({
    id: `n${index}`,
    kind: 'note',
    x: 0,
    y: index,
    w: 1,
    h: 1,
  }))
  assert.equal(canAdd(full, 'note'), false)
})
