import assert from 'node:assert/strict'
import { test } from 'node:test'
import { elapsed, formatDateTime, formatTime, localInputToMs, msToLocalInput } from './time.js'

test('a local date and time goes to its input and back', () => {
  const pad = (n) => String(n).padStart(2, '0')
  for (const ms of [new Date(2026, 10, 4, 10, 30).getTime(), new Date(2026, 6, 1, 0, 5).getTime(), 0]) {
    const d = new Date(ms)
    // What the form of the incident wrote with the local getters.
    const byGetters = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
    assert.equal(msToLocalInput(ms), byGetters)
    assert.equal(localInputToMs(msToLocalInput(ms)), ms)
  }
  assert.equal(msToLocalInput(new Date(2026, 10, 4, 10, 30, 45, 500).getTime()).slice(-5), '10:30')
  for (const none of [null, undefined, NaN, Infinity]) assert.equal(msToLocalInput(none), '')
  for (const none of ['', null, undefined, 'not a time']) assert.equal(localInputToMs(none), null)
})

test('the time since a moment reads as a clock', () => {
  const now = Date.UTC(2026, 10, 4, 10, 30)
  assert.equal(elapsed(new Date(now - 125000).toISOString(), now), '02:05')
  assert.equal(elapsed(new Date(now - 3725000).toISOString(), now), '62:05')
  assert.equal(elapsed(new Date(now + 5000).toISOString(), now), '00:00')
  assert.equal(elapsed(null, now), '00:00')
})

test('a time of day is the end of the date and time, whatever the language of the browser', () => {
  const ms = new Date(2026, 10, 4, 14, 5, 9).getTime()
  assert.equal(formatTime(ms), '14:05:09')
  assert.equal(formatDateTime(ms), '04/11/2026, 14:05:09')
  assert.equal(formatTime(NaN), '—')
})
