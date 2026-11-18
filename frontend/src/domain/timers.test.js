import assert from 'node:assert/strict'
import { test } from 'node:test'
import { formatValue } from './fields.js'
import {
  anyRunning,
  hoursText,
  notificationKind,
  safeLink,
  slaOf,
  slaProblem,
  slaRows,
  span,
  storedTimer,
  timerLine,
} from './timers.js'

test('a length of time in words', () => {
  assert.equal(span(0), '0 s')
  assert.equal(span(45), '45 s')
  assert.equal(span(720), '12 min')
  assert.equal(span(4800), '1 h 20 min')
  assert.equal(span(7200), '2 h')
  assert.equal(span(2 * 86400 + 3 * 3600), '2 d 3 h')
  assert.equal(span(3 * 86400), '3 d')
  assert.equal(span(-5), '0 s')
})

test('what a timer says', () => {
  const running = { state: 'running', elapsedS: 600, dueS: 3600, remainingS: 3000, breached: false }
  assert.deepEqual(timerLine(running), { text: '50 min left · of 1 h', tone: 'ok' })
  assert.deepEqual(timerLine({ ...running, elapsedS: 4200, remainingS: -600, breached: true }), {
    text: '10 min over · of 1 h',
    tone: 'late',
  })
  assert.deepEqual(timerLine({ state: 'running', elapsedS: 90, dueS: null }), { text: 'running · 2 min', tone: 'ok' })
  assert.deepEqual(timerLine({ state: 'paused', elapsedS: 600 }), { text: 'paused at 10 min', tone: 'muted' })
  assert.deepEqual(timerLine({ state: 'stopped', elapsedS: 600, dueS: 3600 }), { text: 'took 10 min', tone: 'muted' })
  assert.deepEqual(timerLine({ state: 'stopped', elapsedS: 4200, dueS: 3600, breached: true }), {
    text: 'took 1 h 10 min · 10 min over',
    tone: 'late',
  })
  assert.equal(timerLine({ state: 'idle' }).text, 'not started')
  assert.equal(anyRunning([{ state: 'stopped' }, { state: 'running' }]), true)
  assert.equal(anyRunning([{ state: 'paused' }]), false)

  // Where a field of the registry is shown as text, a timer is what it holds, in a few words.
  assert.equal(storedTimer({ state: 'running', accumulated_s: 0 }), 'running')
  assert.equal(
    storedTimer({ state: 'stopped', accumulated_s: 720, breached_at: '2026-01-01' }),
    'stopped at 12 min · past its time',
  )
  assert.equal(storedTimer(null), '')
  assert.equal(formatValue({ type: 'timer' }, { state: 'paused', accumulated_s: 60 }), 'paused at 1 min')
})

test('the SLA of a type as the form of Settings edits it', () => {
  const fields = [
    { name: 'severity', type: 'choice', appliesTo: 'incident' },
    { name: 'time_to_assign', label: 'Time to assign', type: 'timer', appliesTo: 'incident' },
    { name: 'time_to_close', label: 'Time to close', type: 'timer', appliesTo: 'incident' },
  ]
  const type = {
    sla: [{ field: 'time_to_assign', minutes: 30, bySeverity: { critical: 5 }, businessHours: true }],
  }
  const rows = slaRows(type, fields)
  assert.deepEqual(
    rows.map((row) => [row.field, row.on, row.minutes, row.bySeverity.critical, row.businessHours]),
    [
      ['time_to_assign', true, '30', '5', true],
      ['time_to_close', false, '', '', false],
    ],
  )
  assert.equal(slaProblem(rows), null)
  assert.deepEqual(slaOf(rows), type.sla)
  const turnedOn = rows.map((row) => (row.field === 'time_to_close' ? { ...row, on: true } : row))
  assert.equal(slaProblem(turnedOn), 'Time to close: say how many minutes are allowed')
  const wrong = rows.map((row) => ({ ...row, bySeverity: { ...row.bySeverity, high: 'soon' } }))
  assert.equal(slaProblem(wrong), 'Time to assign: the time for high is a number of minutes')
  assert.deepEqual(slaOf([]), [])
  assert.equal(hoursText({ startHour: 8, endHour: 18, flagWeekends: true }), '08:00–18:00 UTC, Monday to Friday')
  assert.equal(hoursText({ startHour: 0, endHour: 24, flagWeekends: false }), '00:00–24:00 UTC, every day')
})

test('a notification: its kind in a word, and only a path of Nik as its link', () => {
  assert.equal(notificationKind('task.overdue'), 'overdue')
  assert.equal(notificationKind('sla.breached'), 'SLA')
  assert.equal(notificationKind('something'), 'notice')
  assert.equal(safeLink('/tasks/abc'), '/tasks/abc')
  assert.equal(safeLink('//evil.example/x'), null)
  assert.equal(safeLink('https://evil.example'), null)
  assert.equal(safeLink(''), null)
})
