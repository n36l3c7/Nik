import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  durationWords,
  encryptionStatus,
  planLines,
  restartText,
  rotating,
  rotationPercent,
  rotationStatus,
  sourceText,
} from './keys.js'

const bytes = (count) => `${count} B`
const date = (iso) => `on ${iso.slice(0, 10)}`

test('a length of time is said in words', () => {
  assert.equal(durationWords(0), '0 seconds')
  assert.equal(durationWords(1), '1 second')
  assert.equal(durationWords(59), '59 seconds')
  assert.equal(durationWords(60), '1 minute')
  assert.equal(durationWords(3540), '59 minutes')
  assert.equal(durationWords(3600), '1 hour')
  assert.equal(durationWords(7500), '2 hours 5 minutes')
  assert.equal(durationWords(-5), '0 seconds')
  assert.equal(durationWords(undefined), '0 seconds')
})

test('where a key comes from is said, and the environment is the one to move away from', () => {
  assert.equal(sourceText({ source: 'file' }).text, 'a file')
  assert.equal(sourceText({ source: 'file' }).color, 'emerald')
  assert.equal(sourceText({ source: 'environment' }).color, 'amber')
  assert.match(sourceText({ source: 'environment' }).detail, /inspect a container/)
  assert.equal(sourceText({ source: 'default' }).text, 'not set')
  assert.equal(sourceText(null).text, 'not set')
})

test('a change of key says where it stands, and nothing when there is none', () => {
  assert.deepEqual(rotationStatus({ state: 'idle' }), { text: '', color: 'slate', detail: '' })
  assert.deepEqual(rotationStatus(undefined), { text: '', color: 'slate', detail: '' })
  const running = rotationStatus({ state: 'running', total: 40, done: 12 })
  assert.equal(running.text, 'being changed')
  assert.match(running.detail, /^12 of 40 under the new key/)
  assert.match(rotationStatus({ state: 'running' }).detail, /holds both keys/)
  // Never more than the whole.
  assert.match(rotationStatus({ state: 'running', total: 4, done: 9 }).detail, /^4 of 4/)
  const failed = rotationStatus({ state: 'failed', failed: [{ name: 'a.bin', reason: 'it was cut short' }] })
  assert.equal(failed.color, 'red')
  assert.match(failed.detail, /a\.bin: it was cut short.*Keep the earlier key/)
  assert.match(rotationStatus({ state: 'failed' }).detail, /Keep the earlier key/)
  assert.match(rotationStatus({ state: 'verified' }).detail, /read back with it alone\. The earlier key can go/)
})

test('the page reads itself again only while a key is being changed', () => {
  assert.equal(rotating([{ rotation: { state: 'idle' } }, { name: 'DB_PASSWORD' }]), false)
  assert.equal(rotating([{ rotation: { state: 'verified' } }]), false)
  assert.equal(rotating([{ rotation: { state: 'idle' } }, { rotation: { state: 'running' } }]), true)
  assert.equal(rotating(undefined), false)
  assert.equal(rotationPercent({ total: 0 }), null)
  assert.equal(rotationPercent({ total: 8, done: 2 }), 25)
  assert.equal(rotationPercent({ total: 8, done: 80 }), 100)
})

test('a store that is encrypted says since when, and what was converted', () => {
  const fresh = encryptionStatus({ state: 'sealed', since: '2026-11-20T10:00:00Z' }, bytes, date)
  assert.equal(fresh.title, 'Encrypted')
  assert.deepEqual(fresh.lines, ['Every file of the store is encrypted since on 2026-11-20.'])
  assert.equal(fresh.working, false)
  assert.equal(fresh.percent, null)
  const converted = encryptionStatus(
    { state: 'sealed', since: '2026-11-20T10:00:00Z', converted: { files: 3, bytes: 900, seconds: 125 } },
    bytes,
    date,
  )
  assert.equal(converted.lines[1], '3 files from before 6.8 (900 B) were encrypted in 2 minutes.')
})

test('a store being encrypted says how far it is, how long is left, and what is stuck', () => {
  const status = {
    state: 'converting',
    total: { files: 10, bytes: 1000 },
    done: { files: 4, bytes: 250 },
    left: { files: 6, bytes: 750 },
    secondsLeft: 90,
    bytesPerSecond: 8,
    stuckCount: 0,
  }
  const shown = encryptionStatus(status, bytes, date)
  assert.equal(shown.title, 'Encrypting')
  assert.equal(shown.percent, 25)
  assert.equal(shown.working, true)
  assert.match(shown.lines[0], /^4 of 10 files from before 6\.8 are encrypted \(250 B of 1000 B\)\. New files/)
  assert.equal(shown.lines[1], 'About 2 minutes left, at 8 B a second.')

  const stuck = encryptionStatus({ ...status, stuckCount: 1 }, bytes, date)
  assert.equal(stuck.title, 'Stuck')
  assert.equal(stuck.color, 'red')
  assert.match(stuck.lines.at(-1), /^1 file could not be encrypted and is still in clear/)
  assert.match(
    encryptionStatus({ ...status, stuckCount: 2 }, bytes, date).lines.at(-1),
    /^2 files .* are still in clear/,
  )

  const paused = encryptionStatus({ ...status, state: 'paused', pausedBy: 'admin' }, bytes, date)
  assert.equal(paused.title, 'Paused')
  assert.equal(paused.working, false)
  assert.equal(paused.lines[1], 'Paused by admin: 6 files (750 B) are still in clear on the disk.')

  const starting = encryptionStatus({ state: 'starting' }, bytes, date)
  assert.equal(starting.working, true)
  assert.equal(starting.percent, null)
  assert.equal(encryptionStatus(null, bytes, date).title, 'Looking at the store')
})

test('the dialog of a change says what will be touched and what restarts', () => {
  const plan = {
    items: [
      { what: 'credential', count: 12 },
      { what: 'SMTP password', count: 0 },
      { what: 'second factor of an account', count: 3 },
    ],
    restarts: ['api', 'automation'],
  }
  assert.deepEqual(planLines(plan), ['12 × credential', '3 × second factor of an account'])
  assert.deepEqual(planLines(null), [])
  assert.match(restartText(plan), /^The containers api and automation restart twice/)
  assert.match(restartText({ restarts: ['api'] }), /^The container api restarts twice/)
  assert.equal(restartText({ restarts: [] }), '')
})
