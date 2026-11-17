import assert from 'node:assert/strict'
import { test } from 'node:test'
import { duration, inputValues, isFinished, nodeStatuses, runnable, stepLine, stepsOf, triggerLabel } from './runs.js'

const step = (node, status, extra = {}) => ({ node, status, port: null, attempt: 1, itemIndex: null, ...extra })

test('a node is coloured by the worst of its steps', () => {
  const steps = [
    step('start', 'done'),
    step('loop', 'waiting', { waiting: 'each' }),
    step('note', 'done', { itemIndex: 0 }),
    step('note', 'failed', { itemIndex: 1 }),
    step('note', 'running', { itemIndex: 2 }),
    step('skip', 'skipped'),
  ]
  assert.deepEqual(nodeStatuses(steps), { start: 'done', loop: 'waiting', note: 'failed', skip: 'skipped' })
  assert.deepEqual(nodeStatuses(null), {})
  assert.equal(stepsOf(steps, 'note').length, 3)
  assert.ok(isFinished('stopped') && !isFinished('waiting'))
})

test('durations read as a person would say them', () => {
  const at = (ms) => new Date(Date.UTC(2026, 10, 17, 10, 0, 0) + ms).toISOString()
  assert.equal(duration(at(0), at(38)), '38 ms')
  assert.equal(duration(at(0), at(4200)), '4.2 s')
  assert.equal(duration(at(0), at(42_000)), '42 s')
  assert.equal(duration(at(0), at(3 * 60_000 + 20_000)), '3 min')
  assert.equal(duration(at(0), at(125 * 60_000)), '2 h 5 min')
  assert.equal(duration(at(0), at(3 * 3600_000)), '3 h')
  assert.equal(duration(at(0), at(72 * 3600_000)), '3 d')
  assert.equal(duration(at(0), null, Date.parse(at(5000))), '5.0 s')
  assert.equal(duration('nonsense', at(0)), '')
})

test('a step says what happened in a line', () => {
  assert.equal(stepLine(step('a', 'failed', { error: 'HTTP 503' })), 'HTTP 503')
  assert.equal(stepLine(step('a', 'waiting', { waiting: 'approval' })), 'waiting for an approval')
  assert.equal(
    stepLine(step('a', 'skipped', { error: 'Skipped: the approval was not answered in time' })).slice(0, 7),
    'Skipped',
  )
  const done = step('a', 'done', {
    port: 'yes',
    attempt: 2,
    itemIndex: 2,
    startedAt: '2026-11-17T10:00:00.000Z',
    finishedAt: '2026-11-17T10:00:00.038Z',
  })
  assert.equal(stepLine(done), 'yes · 2nd try · item 3 · 38 ms')
  assert.equal(stepLine(step('a', 'done', { port: 'out' })), '')
  assert.equal(stepLine(step('a', 'done', { attempt: 11 })), '11th try')
  assert.equal(stepLine(null), '')
})

test('what started a run, and which playbooks can be run by hand', () => {
  assert.equal(triggerLabel({ trigger: 'manual' }), 'by hand')
  assert.equal(triggerLabel({ trigger: 'incident.created' }), 'incident.created')
  assert.equal(triggerLabel({}), 'unknown')
  const playbooks = [
    { name: 'a', version: 2, triggerConfig: { manual: true } },
    { name: 'b', version: 1, triggerConfig: { event: 'incident.created' } },
    { name: 'c', version: null, triggerConfig: { manual: true } },
  ]
  assert.deepEqual(
    runnable(playbooks).map((playbook) => playbook.name),
    ['a'],
  )
  assert.deepEqual(
    runnable(playbooks, { dry: true }).map((playbook) => playbook.name),
    ['a', 'b'],
  )
})

test('the inputs of a run are sent as their types say', () => {
  const inputs = [
    { name: 'host', type: 'text', required: true },
    { name: 'count', type: 'number' },
    { name: 'urgent', type: 'bool' },
    { name: 'tags', type: 'list' },
    { name: 'extra', type: 'object' },
    { name: 'left_out', type: 'text' },
  ]
  assert.deepEqual(
    inputValues(inputs, { host: ' evil.example ', count: '3', urgent: 'true', tags: 'a, b\nc', extra: '{"x": 1}' }),
    { host: 'evil.example', count: 3, urgent: true, tags: ['a', 'b', 'c'], extra: { x: 1 } },
  )
  assert.deepEqual(inputValues(inputs, { host: 'x', tags: '["one"]' }), { host: 'x', tags: ['one'] })
  assert.throws(() => inputValues(inputs, {}), /"host" is required/)
  assert.throws(() => inputValues(inputs, { host: 'x', count: 'many' }), /"count" is a number/)
  assert.throws(() => inputValues(inputs, { host: 'x', extra: 'nope' }), /"extra" is an object/)
  assert.deepEqual(inputValues(null, {}), {})
})
