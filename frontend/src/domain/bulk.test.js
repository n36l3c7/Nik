import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  canConfirm,
  closeAsk,
  confirmBody,
  counted,
  indicatorRef,
  jobClean,
  jobEnded,
  jobLine,
  jobProgress,
  notable,
  planWords,
  resultWords,
  retryCount,
} from './bulk.js'
import { amountText, percentOf } from './transfers.js'

const plan = (more = {}) => ({
  list: 'incidents',
  count: 12,
  applies: 12,
  notes: [],
  limit: 5000,
  over: false,
  inline: true,
  typed: null,
  ...more,
})

test('rows are counted in the words of their list', () => {
  assert.equal(counted(1, 'incidents'), '1 incident')
  assert.equal(counted(1284, 'indicators'), '1,284 indicators')
  assert.equal(counted(2, 'elsewhere'), '2 items')
  assert.equal(indicatorRef({ type: 'url', value: 'http://a.example/x:1' }), 'url:http://a.example/x:1')
})

test('a job says how far it is in items, and the tray shows them as items', () => {
  const job = { state: 'running', total: 500, done: 100, skipped: 15, refused: 4, failed: 1, pending: 380 }
  assert.deepEqual(jobProgress(job), { sent: 120, total: 500, items: true })
  assert.equal(percentOf(jobProgress(job)), 24)
  assert.equal(amountText(jobProgress(job)), '120 of 500')
  assert.equal(amountText({ sent: 2048, total: 4096 }), '2.0 KB of 4.0 KB')
  assert.equal(jobEnded(job), false)
  assert.equal(retryCount(job), 0)
  assert.equal(jobLine(job), 'Running: 100 done · 15 skipped · 4 refused · 1 failed · 380 not done')
  assert.equal(jobLine({ ...job, cancelling: true }).startsWith('Stopping'), true)
})

test('a result says only what there is', () => {
  assert.equal(
    resultWords({ done: 1280, skipped: 3, refused: 1, failed: 0, pending: 0 }),
    '1,280 done · 3 skipped · 1 refused',
  )
  assert.equal(resultWords({ done: 0, skipped: 0, refused: 0, failed: 0, pending: 0 }), 'nothing to do')
  assert.equal(jobClean({ state: 'done', done: 4, skipped: 0, refused: 0, failed: 0, pending: 0 }), true)
  assert.equal(jobClean({ state: 'done', done: 4, skipped: 1, refused: 0, failed: 0, pending: 0 }), false)
  assert.equal(jobClean({ state: 'cancelled', done: 4, skipped: 0, refused: 0, failed: 0, pending: 2 }), false)
  assert.equal(retryCount({ state: 'cancelled', failed: 1, pending: 2 }), 3)
  assert.equal(jobLine({ state: 'failed', done: 2, pending: 3 }), 'Given up: 2 done · 3 not done')
})

test('the confirmation says what applies, what is set in motion and how it runs', () => {
  const words = planWords(
    plan({ applies: 9, notes: ['2 of these are mirrored Out: their tickets will be updated, one update for each'] }),
  )
  assert.deepEqual(words.lines, [
    'It applies to 9 of 12: the others are left as they are.',
    '2 of these are mirrored Out: their tickets will be updated, one update for each',
    'It is done at once.',
  ])
  assert.equal(words.problem, null)
  assert.match(planWords(plan({ inline: false })).lines[0], /in the background/)
})

test('what cannot be asked for is said instead of being sent', () => {
  assert.equal(planWords(plan({ count: 0, applies: 0 })).problem, 'Nothing is selected by that.')
  assert.equal(planWords(plan({ applies: 0 })).problem, 'It applies to none of them.')
  assert.match(planWords(plan({ count: 6200, applies: 6200, over: true })).problem, /6,200 incidents.*5,000 at most/)
  assert.equal(canConfirm(plan({ over: true }), ''), false)
  assert.equal(canConfirm(plan(), ''), true)
})

test('a destructive action waits for its words, typed as they are shown', () => {
  const grave = plan({ typed: 'delete 12' })
  assert.equal(canConfirm(grave, ''), false)
  assert.equal(canConfirm(grave, 'delete 11'), false)
  assert.equal(canConfirm(grave, ' delete 12 '), true)
  assert.deepEqual(confirmBody(grave, ' delete 12 ', false), { typed: 'delete 12' })
  assert.deepEqual(confirmBody(plan(), '', true), { count: 12 })
  assert.deepEqual(confirmBody(plan(), '', false), {})
})

test('closing asks what the type wants when the incidents are of one type', () => {
  const types = [
    {
      id: 't1',
      closeReasons: ['Resolved', 'False positive'],
      fields: [{ name: 'verdict', requiredOnClose: true }, { name: 'x' }],
    },
    { id: 'unclassified', closeReasons: [] },
  ]
  const one = closeAsk([{ type: 't1' }, { type: 't1' }], types)
  assert.deepEqual([one.reasons, one.wanted, one.mixed], [['Resolved', 'False positive'], ['verdict'], false])
  const mixed = closeAsk([{ type: 't1' }, { type: '' }], types)
  assert.deepEqual([mixed.type, mixed.reasons, mixed.mixed], [null, [], true])
  assert.equal(closeAsk([], types).mixed, false)
})

test('a result shows first what was not done', () => {
  const items = [
    { ref: 'a', state: 'done' },
    { ref: 'b', state: 'skipped' },
    { ref: 'c', state: 'failed' },
    { ref: 'd', state: 'refused' },
  ]
  assert.deepEqual(
    notable(items).map((item) => item.ref),
    ['c', 'd', 'b'],
  )
})
