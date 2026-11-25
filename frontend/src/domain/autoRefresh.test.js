import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  CHOICES,
  DEFAULT_CHOICE,
  dashboardChoices,
  effectiveSeconds,
  labelOfSeconds,
  clockTime,
  dueIn,
  nextAction,
  nextTick,
  readChoice,
  refreshNote,
  secondsOf,
  shouldReload,
  storageKey,
  writeChoice,
} from './autoRefresh.js'

const memory = (start = {}) => {
  const data = { ...start }
  return { data, getItem: (key) => (key in data ? data[key] : null), setItem: (key, value) => (data[key] = value) }
}
const broken = {
  getItem() {
    throw new Error('blocked')
  },
  setItem() {
    throw new Error('blocked')
  },
}

test('the choices are off, then 30 seconds to 30 minutes, and off is the default', () => {
  assert.deepEqual(
    CHOICES.map((choice) => [choice.id, choice.seconds]),
    [
      ['off', 0],
      ['30s', 30],
      ['1m', 60],
      ['5m', 300],
      ['10m', 600],
      ['30m', 1800],
    ],
  )
  assert.equal(DEFAULT_CHOICE, 'off')
  assert.equal(secondsOf('5m'), 300)
  assert.equal(secondsOf('nonsense'), 0)
})

test('the choice is kept for each account', () => {
  const storage = memory()
  assert.equal(readChoice(storage, 'ada'), 'off')
  writeChoice(storage, 'ada', '5m')
  assert.equal(storage.data['nik.incidents.autoRefresh:ada'], '5m')
  assert.equal(readChoice(storage, 'ada'), '5m')
  assert.equal(readChoice(storage, 'bob'), 'off')
})

test('the choice is kept for each account and each scope, apart from the list and from the other scopes', () => {
  const storage = memory()
  writeChoice(storage, 'ada', '1m', 'dashboards.d1')
  writeChoice(storage, 'ada', '10m', 'dashboards.d2')
  assert.equal(storageKey('ada', 'dashboards.d1'), 'nik.autoRefresh.dashboards.d1:ada')
  assert.equal(readChoice(storage, 'ada', 'dashboards.d1'), '1m')
  assert.equal(readChoice(storage, 'ada', 'dashboards.d2'), '10m')
  assert.equal(readChoice(storage, 'bob', 'dashboards.d1'), 'default')
  assert.equal(readChoice(storage, 'ada'), 'off')
})

test('on a dashboard nothing stored, or an unknown id, follows the dashboard; on the list it is off', () => {
  const scope = 'dashboards.d1'
  assert.equal(readChoice(memory(), 'ada', scope), 'default')
  assert.equal(readChoice(memory({ [storageKey('ada', scope)]: '3h' }), 'ada', scope), 'default')
  assert.equal(readChoice(broken, 'ada', scope), 'default')
  assert.equal(readChoice(memory({ [storageKey('ada')]: 'default' }), 'ada'), 'off')
  const storage = memory()
  writeChoice(storage, 'ada', 'default', scope)
  assert.equal(readChoice(storage, 'ada', scope), 'default')
  writeChoice(storage, 'ada', 'default')
  assert.equal(storage.data[storageKey('ada')], undefined)
})

test('the dashboard pace is followed, an explicit pace or an explicit Off beats it', () => {
  assert.equal(effectiveSeconds('default', 60), 60)
  assert.equal(effectiveSeconds('default', 0), 0)
  assert.equal(effectiveSeconds('default', 90), 90)
  assert.equal(effectiveSeconds('off', 60), 0)
  assert.equal(effectiveSeconds('5m', 60), 300)
  assert.equal(effectiveSeconds('5m'), 300)
  assert.equal(effectiveSeconds('nonsense', 60), 0)
})

test('a pace is said in plain words, odd ones too', () => {
  assert.equal(labelOfSeconds(0), 'Off')
  assert.equal(labelOfSeconds(60), '1 minute')
  assert.equal(labelOfSeconds(300), '5 minutes')
  assert.equal(labelOfSeconds(90), '90 seconds')
  assert.equal(labelOfSeconds(120), '2 minutes')
  assert.equal(labelOfSeconds(900), '15 minutes')
  assert.equal(labelOfSeconds(45), '45 seconds')
  assert.equal(labelOfSeconds(3600), '1 hour')
  const offered = dashboardChoices(90)
  assert.deepEqual(offered[0], { id: 'default', label: 'Dashboard default (90 seconds)' })
  assert.deepEqual(
    offered.slice(1).map((choice) => choice.id),
    CHOICES.map((choice) => choice.id),
  )
  assert.equal(dashboardChoices(0)[0].label, 'Dashboard default (Off)')
})

test('an unknown value is off, and an unknown id is not written', () => {
  const storage = memory({ 'nik.incidents.autoRefresh:ada': '3h' })
  assert.equal(readChoice(storage, 'ada'), 'off')
  writeChoice(storage, 'ada', '2s')
  assert.equal(storage.data['nik.incidents.autoRefresh:ada'], '3h')
})

test('a storage that throws gives off and does not throw on writing', () => {
  assert.equal(readChoice(broken, 'ada'), 'off')
  assert.equal(readChoice(broken, 'ada', 'dashboards.d1'), 'default')
  assert.doesNotThrow(() => writeChoice(broken, 'ada', '1m'))
})

test('dueIn is the time left after the last refresh, never negative', () => {
  assert.equal(dueIn(1000, 60, 11000), 50000)
  assert.equal(dueIn(1000, 60, 61000), 0)
  assert.equal(dueIn(1000, 60, 999999), 0)
  assert.equal(dueIn(null, 60, 5), 60000)
})

test('nextAction: off, a refresh running, paused and a hidden tab do nothing', () => {
  const base = { seconds: 60, lastAt: 0, now: 120000 }
  assert.deepEqual(nextAction({ ...base, seconds: 0 }), { type: 'idle' })
  assert.deepEqual(nextAction({ ...base, refreshing: true }), { type: 'idle' })
  assert.deepEqual(nextAction({ ...base, paused: true }), { type: 'idle' })
  assert.deepEqual(nextAction({ ...base, hidden: true }), { type: 'idle' })
})

test('nextAction waits for what is left, refreshes when overdue (also on the tab becoming visible)', () => {
  assert.deepEqual(nextAction({ seconds: 60, lastAt: 0, now: 20000 }), { type: 'wait', ms: 40000 })
  assert.deepEqual(nextAction({ seconds: 60, lastAt: 0, now: 60000 }), { type: 'refresh' })
  assert.deepEqual(nextAction({ seconds: 60, lastAt: 0, hidden: true, now: 500000 }), { type: 'idle' })
  assert.deepEqual(nextAction({ seconds: 60, lastAt: 0, hidden: false, now: 500000 }), { type: 'refresh' })
})

test('the note says when it was updated, or that it could not be', () => {
  assert.match(clockTime(Date.now()), /^\d{2}\D\d{2}\D\d{2}$/)
  assert.equal(refreshNote({ lastAt: null, error: null }), '')
  assert.match(refreshNote({ lastAt: Date.now(), error: null }), /^Updated \d{2}\D\d{2}\D\d{2}$/)
  assert.match(refreshNote({ lastAt: Date.now(), error: 'x' }), /^Could not refresh · \d{2}\D\d{2}\D\d{2}$/)
  assert.equal(refreshNote({ lastAt: null, error: 'x' }), 'Could not refresh')
})

test('the widgets read again when the tick moved, and only then', () => {
  assert.equal(nextTick(0), 1)
  assert.equal(nextTick(undefined), 1)
  assert.equal(shouldReload(1, 1), false)
  assert.equal(shouldReload(1, 2), true)
})
