import assert from 'node:assert/strict'
import test from 'node:test'
import {
  TEXT_LIMIT,
  fieldItems,
  fieldKind,
  generalItems,
  isMenuKey,
  keyboardPoint,
  linkItems,
  lookupItems,
  menuSections,
  selectionItems,
  textItems,
} from './contextMenu.js'

const ids = (items) => items.map((item) => (item === 'separator' ? '-' : item.id))
const byId = (items, id) => items.find((item) => item.id === id)

test('the general section ends every menu, and is the whole menu where nothing is under the pointer', () => {
  assert.deepEqual(menuSections(), ['general'])
  assert.deepEqual(menuSections({ things: [] }), ['general'])
  assert.deepEqual(menuSections({ things: [{ kind: 'object', depth: 2 }] }), ['object', 'general'])
  assert.deepEqual(menuSections({ page: true }), ['page', 'general'])
})

test('the sections go from the innermost thing outward', () => {
  // A link inside a row that has a menu: the link first, then the row.
  assert.deepEqual(
    menuSections({
      things: [
        { kind: 'link', depth: 0 },
        { kind: 'object', depth: 3 },
      ],
      page: true,
    }),
    ['link', 'object', 'page', 'general'],
  )
  // A row drawn inside a link: the row first.
  assert.deepEqual(
    menuSections({
      things: [
        { kind: 'link', depth: 4 },
        { kind: 'object', depth: 1 },
      ],
    }),
    ['object', 'link', 'general'],
  )
  // The same element is both: what it does comes before where it leads.
  assert.deepEqual(
    menuSections({
      things: [
        { kind: 'link', depth: 0 },
        { kind: 'object', depth: 0 },
      ],
    }),
    ['object', 'link', 'general'],
  )
})

test('selected text comes first, and in a text field it is the field that copies it', () => {
  assert.deepEqual(menuSections({ selection: true, things: [{ kind: 'object', depth: 1 }] }), [
    'selection',
    'object',
    'general',
  ])
  assert.deepEqual(menuSections({ selection: true, things: [{ kind: 'field', depth: 0 }] }), ['field', 'general'])
  // A field that is itself an object with helpers (the query box): its text first, then its helpers.
  assert.deepEqual(
    menuSections({
      things: [
        { kind: 'object', depth: 0 },
        { kind: 'field', depth: 0 },
      ],
    }),
    ['field', 'object', 'general'],
  )
})

test('a cell or a line of text is copied only where nothing else says what to copy', () => {
  assert.deepEqual(menuSections({ things: [{ kind: 'text', depth: 1 }] }), ['text', 'general'])
  assert.deepEqual(
    menuSections({
      things: [
        { kind: 'text', depth: 1 },
        { kind: 'object', depth: 2 },
      ],
    }),
    ['object', 'general'],
  )
  assert.deepEqual(
    menuSections({
      things: [
        { kind: 'field', depth: 0 },
        { kind: 'text', depth: 2 },
      ],
    }),
    ['field', 'general'],
  )
  // A link in a cell: the link, then the cell.
  assert.deepEqual(
    menuSections({
      things: [
        { kind: 'link', depth: 0 },
        { kind: 'text', depth: 1 },
      ],
    }),
    ['link', 'text', 'general'],
  )
})

test('a right-click on the menu itself opens nothing', () => {
  assert.deepEqual(menuSections({ inMenu: true, selection: true, things: [{ kind: 'object', depth: 0 }] }), [])
})

test('which elements are text fields', () => {
  assert.deepEqual(fieldKind({ tag: 'INPUT', type: 'text' }), { kind: 'input', secret: false, ranged: true })
  assert.deepEqual(fieldKind({ tag: 'input' }), { kind: 'input', secret: false, ranged: true })
  assert.deepEqual(fieldKind({ tag: 'INPUT', type: 'search' }), { kind: 'input', secret: false, ranged: true })
  assert.deepEqual(fieldKind({ tag: 'INPUT', type: 'password' }), { kind: 'input', secret: true, ranged: true })
  assert.deepEqual(fieldKind({ tag: 'INPUT', type: 'number' }), { kind: 'input', secret: false, ranged: false })
  assert.deepEqual(fieldKind({ tag: 'TEXTAREA' }), { kind: 'input', secret: false, ranged: true })
  assert.deepEqual(fieldKind({ tag: 'DIV', editable: true }), { kind: 'editable', secret: false, ranged: true })
  assert.deepEqual(fieldKind({ tag: 'DIV', editor: true }), { kind: 'editor', secret: false, ranged: true })
  for (const type of ['checkbox', 'radio', 'file', 'range', 'color', 'date', 'submit', 'button']) {
    assert.equal(fieldKind({ tag: 'INPUT', type }), null, type)
  }
  assert.equal(fieldKind({ tag: 'SELECT' }), null)
  assert.equal(fieldKind({ tag: 'DIV' }), null)
  assert.equal(fieldKind(), null)
})

test('a text field: cut, copy, paste, select all, each enabled as it applies', () => {
  const full = fieldItems({ hasSelection: true })
  assert.deepEqual(ids(full), ['cut', 'copy', 'paste', 'selectAll'])
  assert.ok(full.every((item) => !item.disabled))
  assert.deepEqual(
    full.map((item) => item.hint),
    ['ctrl x', 'ctrl c', 'ctrl v', 'ctrl a'],
  )

  const nothing = fieldItems({ hasSelection: false })
  assert.equal(byId(nothing, 'cut').title, 'Nothing is selected')
  assert.equal(byId(nothing, 'copy').disabled, true)
  assert.equal(byId(nothing, 'paste').disabled, undefined)
  assert.equal(byId(nothing, 'selectAll').disabled, undefined)

  const empty = fieldItems({ empty: true })
  assert.equal(byId(empty, 'selectAll').title, 'The field is empty')
  assert.equal(byId(empty, 'paste').disabled, undefined)
})

test('a read-only field copies and selects, and says why it does not cut or paste', () => {
  const items = fieldItems({ readOnly: true, hasSelection: true })
  assert.equal(byId(items, 'copy').disabled, undefined)
  assert.equal(byId(items, 'selectAll').disabled, undefined)
  assert.equal(byId(items, 'cut').title, 'This field is read-only')
  assert.equal(byId(items, 'paste').title, 'This field is read-only')
})

test('a password is not copied or cut', () => {
  const items = fieldItems({ secret: true, hasSelection: true })
  assert.equal(byId(items, 'copy').title, 'A password is not copied')
  assert.equal(byId(items, 'cut').title, 'A password is not copied')
  assert.equal(byId(items, 'paste').disabled, undefined)
})

test('a field that does not say what is selected gives its whole value', () => {
  const items = fieldItems({ ranged: false, hasSelection: false })
  assert.equal(byId(items, 'copy').disabled, undefined)
  assert.equal(byId(items, 'copy').title, 'The whole value')
  assert.equal(byId(items, 'cut').title, 'The whole value')
  const empty = fieldItems({ ranged: false, empty: true })
  assert.equal(byId(empty, 'copy').title, 'The field is empty')
})

test('an editor with its own undo shows it, with why it cannot be done', () => {
  const items = fieldItems({ hasSelection: true, history: { canUndo: true, canRedo: false } })
  assert.deepEqual(ids(items), ['undo', 'redo', '-', 'cut', 'copy', 'paste', 'selectAll'])
  assert.equal(byId(items, 'undo').disabled, undefined)
  assert.equal(byId(items, 'redo').title, 'Nothing to redo')
  // Read-only: there is nothing to take back.
  assert.deepEqual(ids(fieldItems({ readOnly: true, history: { canUndo: false, canRedo: false } })), [
    'cut',
    'copy',
    'paste',
    'selectAll',
  ])
})

test('text that is an indicator is looked up, searched and added; other text is not', () => {
  const rights = { canRead: true, canWrite: true }
  const items = lookupItems('hxxps://evil[.]top/a', rights)
  assert.deepEqual(ids(items), ['whereSeen', 'searchFor', 'addIndicator'])
  assert.equal(items[0].match.kind, 'url')
  assert.equal(items[0].match.value, 'https://evil.top/a')
  assert.deepEqual(ids(lookupItems('185.220.101.47', { canRead: true })), ['whereSeen', 'searchFor'])
  assert.deepEqual(lookupItems('185.220.101.47'), [])
  assert.deepEqual(lookupItems('a sentence of several words', rights), [])
})

test('selected text is copied, and looked up when it is an indicator', () => {
  assert.deepEqual(ids(selectionItems('some words', { canRead: true })), ['copySelection'])
  assert.deepEqual(ids(selectionItems('paypai.example', { canRead: true, canWrite: true })), [
    'copySelection',
    'whereSeen',
    'searchFor',
    'addIndicator',
  ])
  assert.deepEqual(selectionItems('   '), [])
})

test('a cell is copied alone or with its row; a line of text is copied whole', () => {
  assert.deepEqual(ids(textItems({ cell: 'b', row: 'a\tb\tc' })), ['copyCell', 'copyRow'])
  assert.deepEqual(ids(textItems({ cell: 'only', row: 'only' })), ['copyCell'])
  // An empty cell (a column of buttons): the row is still worth copying.
  assert.deepEqual(ids(textItems({ cell: '', row: 'a\tb' })), ['copyRow'])
  assert.deepEqual(ids(textItems({ cell: '10.0.0.8', row: '10.0.0.8\tseen' }, { canRead: true })), [
    'copyCell',
    'copyRow',
    'whereSeen',
    'searchFor',
  ])
  assert.deepEqual(ids(textItems({ text: 'A line.' })), ['copyText'])
  assert.deepEqual(textItems({ text: '' }), [])
  assert.deepEqual(textItems({ text: 'x'.repeat(TEXT_LIMIT + 1) }), [])
  assert.deepEqual(textItems(), [])
})

test('a link of Nik opens here or in a new tab; one that leaves Nik only in a new tab', () => {
  const origin = 'https://nik.example'
  assert.deepEqual(ids(linkItems({ href: 'https://nik.example/incidents' }, origin)), [
    'followLink',
    'openLinkTab',
    'copyLink',
  ])
  assert.deepEqual(ids(linkItems({ href: '/incidents', newTab: true }, origin)), ['openLinkTab', 'copyLink'])
  const outside = linkItems({ href: 'https://www.virustotal.com/gui/file/abc', newTab: true }, origin)
  assert.deepEqual(ids(outside), ['openLinkTab', 'copyLink'])
  assert.deepEqual(ids(linkItems({ href: 'https://other.example/' }, origin)), ['openLinkTab', 'copyLink'])
})

test('a link that downloads says so, and a file made in the browser has no address to copy', () => {
  const origin = 'https://nik.example'
  const file = linkItems({ href: 'https://nik.example/api/export.zip', download: true }, origin)
  assert.deepEqual(
    file.map((item) => item.label),
    ['Download', 'Copy the address'],
  )
  assert.deepEqual(ids(linkItems({ href: 'blob:https://nik.example/1234', download: true }, origin)), ['followLink'])
  assert.deepEqual(linkItems({ href: 'http://[bad' }, ''), [])
})

test('the general section: what is true on every page, and less before signing in', () => {
  const signedIn = generalItems({ signedIn: true, canRead: true })
  assert.deepEqual(ids(signedIn), ['search', 'shortcuts', 'back', 'copyAddress'])
  assert.deepEqual(
    signedIn.map((item) => item.hint ?? ''),
    ['ctrl k', '?', 'alt ←', ''],
  )
  // An account that reads nothing has nothing to search.
  assert.deepEqual(ids(generalItems({ signedIn: true, canRead: false })), ['shortcuts', 'back', 'copyAddress'])
  // The sign-in page.
  assert.deepEqual(ids(generalItems()), ['back', 'copyAddress'])
  const first = generalItems({ canGoBack: false })
  assert.equal(byId(first, 'back').disabled, true)
  assert.equal(byId(first, 'back').title, 'There is no page before this one')
  // Never empty, and never an entry without a name.
  assert.ok(first.every((item) => item.label))
})

test('the keys that ask for the menu', () => {
  assert.equal(isMenuKey({ key: 'ContextMenu' }), true)
  assert.equal(isMenuKey({ key: 'F10', shiftKey: true }), true)
  assert.equal(isMenuKey({ key: 'F10' }), false)
  assert.equal(isMenuKey({ key: 'F10', shiftKey: true, ctrlKey: true }), false)
  assert.equal(isMenuKey({ key: 'a' }), false)
  assert.equal(isMenuKey(), false)
})

test('the menu asked for by the keyboard opens on what has the focus, inside the window', () => {
  const viewport = { width: 1000, height: 800 }
  assert.deepEqual(keyboardPoint({ left: 100, top: 200, width: 300, height: 30 }, viewport), { x: 124, y: 215 })
  assert.deepEqual(keyboardPoint({ left: 100, top: 200, width: 20, height: 20 }, viewport), { x: 110, y: 210 })
  // Scrolled out of the window: brought back in.
  assert.deepEqual(keyboardPoint({ left: -500, top: 2000, width: 100, height: 100 }, viewport), { x: 8, y: 792 })
  // Nothing has the focus.
  assert.deepEqual(keyboardPoint(null, viewport), { x: 500, y: 267 })
})
