import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  BUTTONS_MAX,
  DEFAULT_BACKGROUND,
  DEFAULT_COLOR,
  againLabel,
  argsFor,
  cleanButtons,
  contrast,
  contrastText,
  fieldTree,
  fieldsOfType,
  hexColor,
  lowContrast,
  luminance,
  mergeRuns,
  newButton,
  runLabel,
  shownValue,
  sourceText,
  tally,
  tookText,
} from './scriptButtons.js'

test('a colour is kept as #rrggbb, however it was typed', () => {
  assert.equal(hexColor('#8B1A1A'), '#8b1a1a')
  assert.equal(hexColor(' ffffff '), '#ffffff')
  assert.equal(hexColor('#abc'), '#aabbcc')
  assert.equal(hexColor('abc'), '#aabbcc')
  for (const wrong of ['', 'red', '#12345', '#1234567', '#gggggg', null, undefined, 12]) {
    assert.equal(hexColor(wrong), null, String(wrong))
  }
})

test('the contrast of a button is the ratio of WCAG, and low under 4.5 : 1', () => {
  assert.equal(luminance('#000000'), 0)
  assert.equal(luminance('#ffffff'), 1)
  assert.equal(luminance('nonsense'), null)
  assert.equal(contrast('#000000', '#ffffff'), 21)
  assert.equal(contrast('#ffffff', '#000000'), 21)
  assert.equal(contrast('#777777', '#777777'), 1)
  assert.equal(contrast('#ffffff', 'red'), null)
  // The red of the mock-up with white text.
  assert.equal(contrastText(contrast('#8b1a1a', '#ffffff')), '9.2 : 1')
  // #767676 on white is the lightest grey that passes: never rounded up over the line.
  assert.equal(contrastText(contrast('#777777', '#ffffff')), '4.4 : 1')
  assert.equal(contrastText(null), '')
  assert.equal(lowContrast({ background: '#777777', color: '#ffffff' }), true)
  assert.equal(lowContrast({ background: '#767676', color: '#ffffff' }), false)
  assert.equal(lowContrast({ background: '#8b1a1a', color: '#ffffff' }), false)
  // The colours of a button nobody coloured can be read.
  assert.equal(lowContrast(newButton()), false)
  assert.equal(lowContrast({}), false)
})

test('the buttons of a widget are kept with what each needs and no more', () => {
  const kept = cleanButtons([
    {
      label: '  Block the sender  ',
      background: '#8B1A1A',
      color: 'white',
      script: 'BlockSender',
      args: { address: '{{ sender_address }}', reason: '   ', 'Bad-Name': 'x', urls: '{{ urls_in_mail }}' },
      extra: 'dropped',
    },
    { label: '   ' },
    null,
    'nonsense',
    { label: 'Later' },
  ])
  assert.deepEqual(kept, [
    {
      label: 'Block the sender',
      background: '#8b1a1a',
      color: DEFAULT_COLOR,
      script: 'BlockSender',
      args: { address: '{{ sender_address }}', urls: '{{ urls_in_mail }}' },
    },
    { label: 'Later', background: DEFAULT_BACKGROUND, color: DEFAULT_COLOR, script: '', args: {} },
  ])
  assert.deepEqual(cleanButtons('nonsense'), [])
  assert.equal(cleanButtons(Array.from({ length: 20 }, (_, index) => ({ label: `b${index}` }))).length, BUTTONS_MAX)
  assert.equal(cleanButtons([{ label: 'x'.repeat(80) }])[0].label.length, 40)
  // A script that lost an argument: its template goes with it.
  const script = { name: 'BlockSender', arguments: [{ name: 'address' }, { name: 'reason' }] }
  assert.deepEqual(argsFor(kept[0], script), { address: '{{ sender_address }}' })
  assert.deepEqual(argsFor(kept[0], null), {})
})

test('the fields of the type are what a template can be picked from', () => {
  const known = {
    status: { name: 'status', label: 'Status', type: 'choice' },
    sender_address: { name: 'sender_address', label: 'Sender address', type: 'text' },
    time_to_close: { name: 'time_to_close', label: 'Time to close', type: 'timer' },
  }
  const layout = {
    sections: [
      { id: 'key', fields: ['status', 'gone'] },
      { id: 'mail', fields: ['sender_address', 'time_to_close', 'status'] },
    ],
  }
  const fields = fieldsOfType(layout, known)
  assert.deepEqual(
    fields.map((field) => field.name),
    ['status', 'sender_address', 'time_to_close'],
  )
  const tree = fieldTree(fields)
  assert.deepEqual(
    tree.map((root) => root.name),
    ['fields', 'incident'],
  )
  // A field is written by its name alone; a timer is not a value to give a script.
  assert.deepEqual(tree[0].fields, [
    { path: 'status', type: 'choice', description: 'Status' },
    { path: 'sender_address', type: 'text', description: 'Sender address' },
  ])
  const paths = tree[1].fields.map((field) => field.path)
  for (const path of ['incident.number', 'incident.host', 'incident.user']) assert.ok(paths.includes(path), path)
  assert.deepEqual(
    fieldTree([]).map((root) => root.name),
    ['incident'],
  )
})

test('what the dialog of a press says', () => {
  assert.equal(shownValue('a text'), 'a text')
  assert.equal(shownValue(['a', 'b', 3]), 'a, b, 3')
  assert.equal(shownValue({ a: 1 }), '{"a":1}')
  assert.equal(shownValue([{ a: 1 }]), '[{"a":1}]')
  assert.equal(shownValue(null), '')
  assert.equal(shownValue(0), '0')
  assert.equal(sourceText({ source: { label: 'Sender address' } }), 'from Sender address')
  assert.equal(sourceText({ source: { label: 'URLs in the mail' }, count: 3 }), 'from URLs in the mail · 3 values')
  assert.equal(sourceText({ source: null }), 'set in the button')
  assert.equal(runLabel(1), 'Run')
  assert.equal(runLabel(3), 'Run 3 times')
  assert.equal(againLabel(1), 'Run the failed one again')
  assert.equal(againLabel(3), 'Run the 3 failed ones again')
  assert.equal(tookText(340), '340 ms')
  assert.equal(tookText(1234), '1.2 s')
  assert.equal(tookText(125_000), '2 min 5 s')
  assert.equal(tookText(null), '')
})

test('the runs of a press are listed with where each is', () => {
  const started = [
    { index: 0, item: 'a', runId: 'r1' },
    { index: 1, item: 'b', runId: 'r2' },
    { index: 2, item: 'c', runId: 'r3' },
  ]
  const runs = mergeRuns(started, [
    { runId: 'r1', status: 'done', durationMs: 1200 },
    { runId: 'r2', status: 'failed', durationMs: 900, error: 'refused' },
  ])
  assert.deepEqual(runs, [
    { index: 0, item: 'a', runId: 'r1', status: 'done', durationMs: 1200, error: null },
    { index: 1, item: 'b', runId: 'r2', status: 'failed', durationMs: 900, error: 'refused' },
    // Not answered for yet: it is running.
    { index: 2, item: 'c', runId: 'r3', status: 'running', durationMs: null, error: null },
  ])
  assert.deepEqual(tally(runs), { running: 1, done: 1, failed: 1 })
  // What was known of a run stays when an answer leaves it out.
  assert.equal(mergeRuns(runs, [])[0].status, 'done')
  assert.deepEqual(tally(null), { running: 0, done: 0, failed: 0 })
})
