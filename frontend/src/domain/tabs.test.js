import assert from 'node:assert/strict'
import { test } from 'node:test'
import { tabStop, tabTarget } from './tabs.js'

const items = [{ id: 'a' }, { id: 'b', disabled: true }, { id: 'c' }, { id: 'd' }]

test('the arrows go round and skip a disabled tab', () => {
  assert.equal(tabTarget('ArrowRight', 0, items), 2)
  assert.equal(tabTarget('ArrowRight', 3, items), 0)
  assert.equal(tabTarget('ArrowLeft', 0, items), 3)
  assert.equal(tabTarget('ArrowLeft', 2, items), 0)
})

test('Home and End go to the first and the last tab that can be chosen', () => {
  assert.equal(tabTarget('Home', 3, items), 0)
  assert.equal(tabTarget('End', 0, [{ id: 'a' }, { id: 'b' }, { id: 'c', disabled: true }]), 1)
})

test("another key, or no tab to choose, is not the row's", () => {
  assert.equal(tabTarget('Enter', 0, items), null)
  assert.equal(tabTarget('ArrowRight', 0, [{ id: 'a', disabled: true }]), null)
})

test('the Tab stop is the selected tab, else the first that can be chosen', () => {
  assert.equal(tabStop('c', items), 2)
  assert.equal(tabStop('b', items), 0)
  assert.equal(tabStop('zzz', items), 0)
  assert.equal(tabStop('a', [{ id: 'a', disabled: true }]), -1)
})
