import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  argsText,
  canBreak,
  canRerun,
  debugLine,
  overridesOf,
  parseObject,
  parseValue,
  stoppedAt,
  toggleBreakpoint,
} from './debug.js'

const STEPS = [
  { id: 's1', node: 'start', status: 'done' },
  { id: 's2', node: 'a', status: 'done', input: { action: 'test.echo', args: { text: 'one', extra: null } } },
  { id: 's3', node: 'b', status: 'waiting', waiting: 'debug', input: { args: { text: 'one two' } } },
]
const RUN = {
  status: 'waiting',
  steps: STEPS,
  approvals: [],
  debug: { breakpoints: ['b'], stepMode: true, at: [{ step: 's3', node: 'b' }] },
}

test('where a debug run is stopped, and what it says of itself', () => {
  assert.deepEqual(
    stoppedAt(RUN).map((step) => step.node),
    ['b'],
  )
  assert.deepEqual(stoppedAt({ steps: STEPS }), [])
  const names = { b: 'Block the host' }
  assert.equal(
    debugLine(RUN, (id) => names[id] ?? id),
    'Stopped before Block the host.',
  )
  assert.equal(debugLine({ ...RUN, status: 'done' }), 'The debug run is over.')
  const going = { ...RUN, status: 'running', debug: { ...RUN.debug, at: [] } }
  assert.equal(debugLine(going), 'Going to the next node…')
  assert.equal(debugLine({ ...going, debug: { ...going.debug, stepMode: false } }), 'Going to the next breakpoint…')
  assert.equal(debugLine({ ...going, approvals: [{ status: 'waiting' }] }), 'Waiting for an approval.')
  assert.equal(debugLine({ status: 'running', steps: [] }), '')
})

test('the arguments of a node as text, and what a person typed back', () => {
  assert.equal(argsText(STEPS[2]), '{\n  "text": "one two"\n}')
  assert.equal(argsText(STEPS[0]), '')
  assert.deepEqual(parseObject(''), { value: null, error: null })
  assert.deepEqual(parseObject('{"text": "typed"}'), { value: { text: 'typed' }, error: null })
  assert.match(parseObject('[1]').error, /are an object/)
  assert.match(parseObject('{nope').error, /^Not valid JSON/)
  // Only what was changed is sent.
  assert.deepEqual(overridesOf(STEPS[1], { text: 'typed', extra: null }), { text: 'typed' })
  assert.equal(overridesOf(STEPS[1], { text: 'one', extra: null }), null)
  assert.equal(overridesOf(STEPS[1], null), null)
  assert.deepEqual(parseValue('{"text": 1}'), { value: { text: 1 }, error: null, empty: false })
  assert.deepEqual(parseValue('"plain"'), { value: 'plain', error: null, empty: false })
  assert.equal(parseValue(' ').empty, true)
  assert.match(parseValue('{').error, /^Not valid JSON/)
})

test('breakpoints, and which nodes can be stopped before or run again', () => {
  assert.deepEqual(toggleBreakpoint(['b'], 'a'), ['b', 'a'])
  assert.deepEqual(toggleBreakpoint(['b', 'a'], 'b'), ['a'])
  assert.deepEqual(toggleBreakpoint(undefined, 'a'), ['a'])
  assert.equal(canBreak({ kind: 'action' }), true)
  assert.equal(canBreak({ kind: 'trigger' }), false)
  assert.equal(canBreak(null), false)
  assert.equal(canRerun(STEPS[1], { kind: 'action' }), true)
  assert.equal(canRerun(STEPS[2], { kind: 'action' }), false) // not over yet
  assert.equal(canRerun(STEPS[0], { kind: 'trigger' }), false)
  assert.equal(canRerun(STEPS[1], { kind: 'for_each' }), false)
})
