import test from 'node:test'
import assert from 'node:assert/strict'
import { asTable, authorLabel, cell, contextWrites, entryLine, threaded } from './warRoom.js'

test('a line of the stream says what happened', () => {
  assert.deepEqual(entryLine({ kind: 'note', body: { text: 'Called the user.' } }), {
    title: '',
    text: 'Called the user.',
    tone: 'note',
  })
  assert.deepEqual(
    entryLine({
      kind: 'result',
      body: { title: 'Open a ticket', what: 'servicenow.create-incident', playbook: 'Ticketing' },
    }),
    {
      title: 'Open a ticket',
      text: 'playbook Ticketing',
      tone: 'ok',
    },
  )
  assert.equal(entryLine({ kind: 'result', body: { title: 'ip', what: 'ip', adhoc: true } }).text, 'ip')
  assert.deepEqual(entryLine({ kind: 'error', body: { title: 'Block', error: 'Refused by the other side' } }), {
    title: 'Block',
    text: 'Refused by the other side',
    tone: 'error',
  })
  assert.deepEqual(entryLine({ kind: 'approval', body: { question: 'Go on?', answer: 'approved', comment: 'fine' } }), {
    title: 'Go on?',
    text: 'approved: fine',
    tone: 'ok',
  })
  assert.equal(
    entryLine({ kind: 'approval', body: { question: 'Go on?', answer: 'expired' } }).text,
    'not answered in time',
  )
  assert.equal(entryLine({ kind: 'command', body: { line: '!ip 1.2.3.4' } }).title, '!ip 1.2.3.4')
  assert.deepEqual(
    entryLine({ kind: 'command', body: { line: '!BlockSender address=a@b.example', button: 'Block the sender' } }),
    {
      title: '!BlockSender address=a@b.example',
      text: 'Pressed: Block the sender',
      tone: 'command',
    },
  )
  assert.equal(entryLine({ kind: 'system', body: { text: 'kept Ticket: edited by anna' } }).tone, 'system')
  assert.equal(authorLabel('nik-automation'), 'automation')
  assert.equal(authorLabel('connector:servicenow'), 'servicenow')
  assert.equal(authorLabel('anna'), 'anna')
})

test('a result is a table when it is a list of flat objects', () => {
  const agents = [
    { name: 'WKS-1', isolated: false },
    { name: 'SRV-2', isolated: true, os: 'Windows' },
  ]
  assert.deepEqual(asTable(agents), { columns: ['name', 'isolated', 'os'], rows: agents })
  // The usual shape of a result: an object with one list in it.
  assert.deepEqual(asTable({ agents, count: 2 }).columns, ['name', 'isolated', 'os'])
  assert.equal(asTable({ a: agents, b: agents }), null)
  assert.equal(asTable([{ name: 'x', nested: { a: 1 } }]), null)
  assert.equal(asTable([]), null)
  assert.equal(asTable('text'), null)
  assert.equal(asTable({ number: 'T-1' }), null)
  assert.equal(cell(true), 'yes')
  assert.equal(cell(null), '')
  assert.equal(cell(12), '12')
})

test('what a step wrote to the context is read from its log', () => {
  assert.deepEqual(contextWrites('sent\n[nik] written to the context: field:ticket, Ticket:t-77, ext.acme.queue'), [
    'field:ticket',
    'Ticket:t-77',
    'ext.acme.queue',
  ])
  assert.deepEqual(contextWrites('nothing of the kind'), [])
  assert.deepEqual(contextWrites(null), [])
})

test('what a command gave is shown under the command', () => {
  const entries = [
    { id: 'a', kind: 'note' },
    { id: 'b', kind: 'command' },
    { id: 'c', kind: 'note' },
    { id: 'd', kind: 'result', parentId: 'b' },
    { id: 'e', kind: 'result', parentId: 'gone' },
  ]
  assert.deepEqual(
    threaded(entries).map((entry) => [entry.id, entry.depth]),
    [
      ['a', 0],
      ['b', 0],
      ['d', 1],
      ['c', 0],
      ['e', 0],
    ],
  )
  assert.deepEqual(threaded(null), [])
})
