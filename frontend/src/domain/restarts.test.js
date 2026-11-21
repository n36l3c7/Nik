import assert from 'node:assert/strict'
import test from 'node:test'
import {
  ANSWERS,
  interruptedSteps,
  restartLine,
  restartLines,
  runStatus,
  safeToRepeatHelp,
  workLine,
  workProgress,
} from './restarts.js'

const at = (ms) => new Date(ms).toISOString().slice(11, 16)

test('the three answers are the ones the server takes, in the order of the buttons', () => {
  assert.deepEqual(
    ANSWERS.map((item) => item.answer),
    ['happened', 'again', 'stop'],
  )
  assert.ok(ANSWERS.every((item) => item.label && item.hint))
})

test('a run that waits at an interrupted step says so, any other says its status', () => {
  assert.equal(runStatus({ status: 'waiting', interrupted: true }), 'interrupted')
  assert.equal(runStatus({ status: 'waiting', interrupted: false }), 'waiting')
  assert.equal(runStatus({ status: 'done' }), 'done')
  assert.equal(runStatus(null), '')
  const steps = [
    { id: 'a', status: 'done' },
    { id: 'b', status: 'interrupted' },
  ]
  assert.deepEqual(
    interruptedSteps(steps).map((step) => step.id),
    ['b'],
  )
  assert.deepEqual(interruptedSteps(undefined), [])
})

test('the history of a step reads as what happened, with who said it', () => {
  const restarts = [
    { at: '2026-11-21T10:02:00+00:00', what: 'interrupted' },
    { at: '2026-11-21T10:02:00+00:00', what: 'waiting' },
    { at: '2026-11-21T10:30:00+00:00', what: 'again', by: 'anna' },
    { at: '2026-11-21T10:31:00+00:00', what: 'something new' },
  ]
  assert.deepEqual(restartLines(restarts, at), [
    'Interrupted by a restart at 10:02',
    'It is not known whether it happened: it waits for a person since 10:02',
    'anna said it did not happen: done again at 10:30',
  ])
  assert.equal(restartLine({ at: '2026-11-21T10:03:00+00:00', what: 'again' }, at), 'Started again at 10:03')
  assert.equal(
    restartLine({ at: '2026-11-21T10:40:00+00:00', what: 'happened', by: 'anna' }, at),
    'anna said it happened: the run went on at 10:40',
  )
  assert.equal(
    restartLine({ at: '2026-11-21T10:40:00+00:00', what: 'stopped', by: 'anna' }, at),
    'anna stopped the run at 10:40',
  )
  assert.equal(
    restartLine({ at: '2026-11-21T10:41:00+00:00', what: 'away' }, at),
    'Its worker was not there at 10:41: taken again a moment later',
  )
  assert.deepEqual(restartLines(null), [])
})

test('a job says when a restart cut it and when it went on', () => {
  const cut = Date.parse('2026-11-21T10:02:00Z') / 1000
  const back = Date.parse('2026-11-21T10:03:00Z') / 1000
  assert.equal(workLine(null, at), '')
  assert.equal(workLine({ state: 'held', attempts: 1, interruptedAt: null }, at), '')
  assert.equal(
    workLine({ state: 'held', attempts: 2, interruptedAt: cut, resumedAt: back }, at),
    'Interrupted by a restart at 10:02, started again at 10:03 (try 2 of 3).',
  )
  assert.equal(
    workLine({ state: 'done', attempts: 1, interruptedAt: cut, resumedAt: back }, at),
    'Interrupted by a restart at 10:02, started again at 10:03.',
  )
  assert.equal(
    workLine({ state: 'wanted', attempts: 1, interruptedAt: cut, resumedAt: null }, at),
    'Interrupted by a restart at 10:02: it starts again by itself within a minute.',
  )
  assert.equal(
    workLine({ state: 'aside', attempts: 3, interruptedAt: cut }, at),
    'Interrupted by a restart at 10:02, 3 times in all: set aside.',
  )
  assert.equal(
    workLine({ state: 'failed', attempts: 1, interruptedAt: cut }, at),
    'Interrupted by a restart at 10:02: it could not be gone on with.',
  )
})

test('how far a job is shows only while it is held', () => {
  assert.equal(
    workProgress({ state: 'held', progress: 'reading the packets (1 of 2)' }),
    'reading the packets (1 of 2)',
  )
  assert.equal(workProgress({ state: 'done', progress: 'left over' }), '')
  assert.equal(workProgress(null), '')
})

test('the help of "Safe to repeat" says what a restart does with the tick on and off', () => {
  assert.match(safeToRepeatHelp(true), /is sent again, whatever its method/)
  assert.match(safeToRepeatHelp(false), /is not sent again: the run waits for a person/)
  assert.notEqual(safeToRepeatHelp(true), safeToRepeatHelp(false))
})
