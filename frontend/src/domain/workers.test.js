import test from 'node:test'
import assert from 'node:assert/strict'
import { lastedWords, notAnswering, workerName, workerStatus } from './workers.js'

const NOW = Date.parse('2027-01-15T08:15:00Z')
const browser = (changes) => ({
  id: 'browser',
  label: 'isolated browser',
  waits: 'addresses cannot be scanned',
  configured: true,
  state: 'up',
  since: '2027-01-15T08:00:00+00:00',
  ...changes,
})

test('how long reads as a person would say it', () => {
  assert.equal(lastedWords(20_000), '1 minute')
  assert.equal(lastedWords(125_000), '2 minutes')
  assert.equal(lastedWords(3_600_000), '1 hour')
  assert.equal(lastedWords(7_500_000), '2 hours 5 minutes')
  assert.equal(lastedWords(undefined), '1 minute')
})

test('a worker says whether it answers, and for how long it has not', () => {
  assert.deepEqual(workerStatus(browser(), NOW), { text: 'answering', color: 'emerald', detail: '' })
  assert.deepEqual(workerStatus(browser({ state: 'failing', since: '2027-01-15T08:14:00+00:00' }), NOW), {
    text: 'not answering',
    color: 'amber',
    detail: 'For 1 minute: addresses cannot be scanned.',
  })
  assert.deepEqual(workerStatus(browser({ state: 'down' }), NOW), {
    text: 'down',
    color: 'red',
    detail: 'For 15 minutes: addresses cannot be scanned.',
  })
  assert.equal(workerStatus(browser({ state: 'down', since: null }), NOW).detail, 'addresses cannot be scanned.')
})

test('a worker that is not configured, or not checked yet, says so and nothing else', () => {
  assert.deepEqual(workerStatus(browser({ configured: false, state: '' }), NOW), {
    text: 'not configured',
    color: 'slate',
    detail: '',
  })
  assert.equal(workerStatus(browser({ state: '', since: null }), NOW).text, 'not checked yet')
  assert.equal(workerStatus(null, NOW).text, 'not configured')
})

test('the name of a worker and how many do not answer', () => {
  assert.equal(workerName(browser()), 'Isolated browser')
  assert.equal(workerName(null), '')
  const rows = [browser(), browser({ state: 'down' }), browser({ state: 'failing' }), browser({ configured: false })]
  assert.equal(notAnswering(rows), 2)
  assert.equal(notAnswering(undefined), 0)
})
