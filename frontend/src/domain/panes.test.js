import assert from 'node:assert/strict'
import { test } from 'node:test'
import { clampWidth, paneKey, readWidth, stepWidth } from './panes.js'

test('a width stays inside the limits of its panel and of the window', () => {
  const limits = { min: 180, max: 420 }
  assert.equal(clampWidth(300, limits), 300)
  assert.equal(clampWidth(20, limits), 180)
  assert.equal(clampWidth(9000, limits), 420)
  assert.equal(clampWidth(300.6, limits), 301)
  assert.equal(clampWidth('abc', limits), 180)
  // A small window: 60 % of it at most, and never under the minimum.
  assert.equal(clampWidth(400, { ...limits, viewport: 500 }), 300)
  assert.equal(clampWidth(400, { ...limits, viewport: 200 }), 180)
})

test('the width of a panel is remembered under its own key, and found where 4.x kept it', () => {
  const storage = (items) => ({ getItem: (key) => items[key] ?? null })
  assert.equal(paneKey('settings.nav'), 'nik.pane.settings.nav')
  assert.equal(readWidth(storage({ 'nik.pane.sidebar': '310' }), 'sidebar'), 310)
  assert.equal(readWidth(storage({ 'nik.sidebarWidth': '288' }), 'sidebar', 'nik.sidebarWidth'), 288)
  assert.equal(
    readWidth(storage({ 'nik.pane.sidebar': '310', 'nik.sidebarWidth': '288' }), 'sidebar', 'nik.sidebarWidth'),
    310,
  )
  assert.equal(readWidth(storage({}), 'sidebar', 'nik.sidebarWidth'), null)
  assert.equal(readWidth(storage({ 'nik.pane.sidebar': 'wide' }), 'sidebar'), null)
  assert.equal(readWidth(storage({ 'nik.pane.sidebar': '-4' }), 'sidebar'), null)
  // A browser that refuses storage: no width, no error.
  const refusing = {
    getItem() {
      throw new Error('denied')
    },
  }
  assert.equal(readWidth(refusing, 'sidebar'), null)
})

test('the arrow that points away from the panel makes it wider', () => {
  const limits = { min: 180, max: 420 }
  assert.equal(stepWidth(300, 'ArrowRight', limits), 316)
  assert.equal(stepWidth(300, 'ArrowLeft', limits), 284)
  assert.equal(stepWidth(300, 'ArrowRight', { ...limits, large: true }), 364)
  assert.equal(stepWidth(410, 'ArrowRight', limits), 420)
  assert.equal(stepWidth(185, 'ArrowLeft', limits), 180)
  assert.equal(stepWidth(300, 'Home', limits), 180)
  assert.equal(stepWidth(300, 'End', limits), 420)
  // A panel on the right of the page has its handle on its left edge.
  assert.equal(stepWidth(300, 'ArrowLeft', { ...limits, edge: 'left' }), 316)
  assert.equal(stepWidth(300, 'ArrowRight', { ...limits, edge: 'left' }), 284)
  assert.equal(stepWidth(300, 'a', limits), null)
  assert.equal(stepWidth(300, 'Tab', limits), null)
})
