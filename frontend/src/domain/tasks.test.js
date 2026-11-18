import assert from 'node:assert/strict'
import { test } from 'node:test'
import { blocks, inline } from './markdown.js'
import {
  answerLines,
  answerOf,
  byUrgency,
  dueText,
  emptyForm,
  missing,
  orderPlans,
  phaseTitle,
  progress,
  statusBadge,
  stepBadge,
  tasksFromPath,
  tasksPath,
} from './tasks.js'
import { entryLine } from './warRoom.js'

const NOW = Date.parse('2026-11-17T10:00:00Z')
const at = (seconds) => NOW / 1000 + seconds

test('the address of the tasks page and of one task', () => {
  assert.equal(tasksFromPath('/incident/i1'), null)
  assert.deepEqual(tasksFromPath('/tasks'), { id: null })
  assert.deepEqual(tasksFromPath('/tasks/abc/'), { id: 'abc' })
  assert.deepEqual(tasksFromPath('/tasks/%E0%A4%A'), { id: null })
  assert.equal(tasksPath(), '/tasks')
  assert.equal(tasksPath('a b'), '/tasks/a%20b')
})

test('what a task is called and when it is due', () => {
  assert.deepEqual(statusBadge({ kind: 'task', status: 'open' }), { label: 'to do', color: 'amber' })
  assert.deepEqual(statusBadge({ kind: 'ask', status: 'open' }), { label: 'asked', color: 'amber' })
  assert.equal(statusBadge({ kind: 'ask', status: 'done' }).label, 'answered')
  assert.equal(statusBadge({ kind: 'ask', status: 'skipped' }).label, 'no answer')
  assert.equal(statusBadge({ kind: 'task', status: 'overdue' }).color, 'red')

  assert.equal(dueText({ status: 'open', dueAt: at(7200) }, NOW), 'due in 2 h')
  assert.equal(dueText({ status: 'open', dueAt: at(20) }, NOW), 'due in 1 min')
  assert.equal(dueText({ status: 'overdue', dueAt: at(-3 * 86400) }, NOW), '3 d late')
  assert.equal(dueText({ status: 'done', dueAt: at(-60) }, NOW), '')
  assert.equal(dueText({ status: 'open', dueAt: null }, NOW), '')

  const sorted = byUrgency([
    { id: 'none', status: 'open', dueAt: null, createdAt: '2026-01-02' },
    { id: 'soon', status: 'open', dueAt: at(60), createdAt: '2026-01-03' },
    { id: 'late', status: 'overdue', dueAt: at(-60), createdAt: '2026-01-04' },
    { id: 'old', status: 'open', dueAt: null, createdAt: '2026-01-01' },
  ])
  assert.deepEqual(
    sorted.map((task) => task.id),
    ['late', 'soon', 'old', 'none'],
  )
})

test('the form of a task: what is missing, what is sent, what was answered', () => {
  const task = {
    kind: 'ask',
    choices: [
      { label: 'Yes', port: 'yes' },
      { label: 'No', port: 'no' },
    ],
    fields: [
      { name: 'badge', label: 'Badge number', type: 'number' },
      { name: 'labels', label: 'Labels', type: 'tags' },
    ],
    inputs: [
      { name: 'serial', label: 'Serial number', type: 'text', required: true },
      { name: 'docked', label: 'Docked', type: 'bool', required: false },
    ],
  }
  const form = emptyForm(task)
  assert.deepEqual(form, {
    choice: '',
    fields: { badge: '', labels: '' },
    values: { serial: '', docked: '' },
    comment: '',
  })
  assert.deepEqual(missing(task, form), ['a choice', 'Badge number', 'Labels', 'Serial number'])
  const filled = {
    choice: 'yes',
    fields: { badge: '4471', labels: 'a, b' },
    values: { serial: 'X1', docked: 'no' },
    comment: ' In the safe ',
  }
  assert.deepEqual(missing(task, filled), [])
  assert.deepEqual(answerOf(task, filled), {
    comment: 'In the safe',
    choice: 'yes',
    fields: { badge: 4471, labels: ['a', 'b'] },
    values: { serial: 'X1', docked: false },
  })
  assert.throws(() => answerOf(task, { ...filled, fields: { badge: 'many' } }), /Badge number is a number/)
  // A plain task sends its comment and nothing else.
  assert.deepEqual(answerOf({ kind: 'task' }, emptyForm({ kind: 'task' })), { comment: '' })

  assert.deepEqual(
    answerLines({
      ...task,
      answer: { choice: 'Yes', fields: { badge: 4471 }, values: { serial: 'X1', docked: false }, comment: 'ok' },
    }),
    [
      { label: 'Answer', text: 'Yes' },
      { label: 'Badge number', text: '4471' },
      { label: 'Serial number', text: 'X1' },
      { label: 'Docked', text: 'no' },
      { label: 'Comment', text: 'ok' },
    ],
  )
  assert.deepEqual(answerLines({ answer: { skipped: 'The run ended (stopped)' } }), [
    { label: 'Skipped', text: 'The run ended (stopped)' },
  ])
  assert.deepEqual(answerLines({}), [])
})

test('the work plan: how far it is, which comes first, what a step says', () => {
  const plan = {
    status: 'waiting',
    phases: [
      { name: 'Triage', steps: [{ status: 'done' }, { status: 'skipped' }] },
      { name: '', steps: [{ status: 'waiting' }, { status: 'none' }, { status: 'failed' }] },
    ],
  }
  assert.deepEqual(progress(plan), { done: 3, total: 5 })
  assert.deepEqual(progress({}), { done: 0, total: 0 })
  assert.equal(phaseTitle(plan.phases[0], false), 'Triage')
  assert.equal(phaseTitle(plan.phases[1], false), 'Other steps')
  assert.equal(phaseTitle({ name: '' }, true), 'Steps')
  assert.deepEqual(
    orderPlans([
      { runId: 'old-done', status: 'done', startedAt: '2026-01-01' },
      { runId: 'new-done', status: 'failed', startedAt: '2026-01-03' },
      { runId: 'live', status: 'waiting', startedAt: '2026-01-02' },
    ]).map((item) => item.runId),
    ['live', 'new-done', 'old-done'],
  )
  assert.equal(stepBadge({ status: 'none' }).label, 'not reached')
  assert.equal(stepBadge({ status: 'pending' }).label, 'running')
  // A step that waits for a task says what the task says.
  assert.equal(stepBadge({ status: 'waiting', task: { kind: 'task', status: 'overdue' } }).label, 'overdue')
  assert.equal(stepBadge({ status: 'done', task: { kind: 'task', status: 'done' } }).label, 'done')
})

test('a task in the War Room is one line', () => {
  const line = (body) => entryLine({ kind: 'task', body })
  assert.deepEqual(line({ title: 'Pull the disk', state: 'asked', for: 'anna' }), {
    title: 'Pull the disk',
    text: 'a task for anna',
    tone: 'ask',
  })
  assert.equal(line({ title: 'x', state: 'given', for: 'the role analyst' }).text, 'given to the role analyst')
  assert.deepEqual(line({ title: 'x', state: 'done', answer: 'Yes', comment: 'fine' }), {
    title: 'x',
    text: 'done: Yes · fine',
    tone: 'ok',
  })
  assert.equal(line({ title: 'x', state: 'done' }).text, 'done')
  assert.equal(line({ title: 'x', state: 'skipped', comment: 'gone' }).text, 'skipped: gone')
})

test('instructions are read as a small Markdown, and nothing in them is a tag', () => {
  assert.deepEqual(inline('Bag it and **label** it, *now*: `dd if=x` [the guide](https://example.org/a).'), [
    { type: 'text', text: 'Bag it and ' },
    { type: 'bold', text: 'label' },
    { type: 'text', text: ' it, ' },
    { type: 'italic', text: 'now' },
    { type: 'text', text: ': ' },
    { type: 'code', text: 'dd if=x' },
    { type: 'text', text: ' ' },
    { type: 'link', text: 'the guide', href: 'https://example.org/a' },
    { type: 'text', text: '.' },
  ])
  // A link that is not http, https or mailto stays text.
  assert.deepEqual(inline('[x](javascript:alert(1))')[0].type, 'text')
  assert.deepEqual(inline('<script>'), [{ type: 'text', text: '<script>' }])
  assert.deepEqual(
    blocks('# Steps\n\nFirst line\nsecond line\n\n- one\n- two\n1. first\n\n```\nrm -rf x\n```\n').map(
      (block) => block.type,
    ),
    ['heading', 'paragraph', 'list', 'list', 'code'],
  )
  const [, paragraph, bullets, numbers, code] = blocks(
    '# Steps\n\nFirst line\nsecond line\n\n- one\n- two\n1. first\n\n```\nrm -rf x\n```\n',
  )
  assert.equal(paragraph.parts[0].text, 'First line second line')
  assert.equal(bullets.items.length, 2)
  assert.equal(numbers.ordered, true)
  assert.equal(code.text, 'rm -rf x')
  assert.deepEqual(blocks(''), [])
})
