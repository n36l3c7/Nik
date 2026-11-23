import test from 'node:test'
import assert from 'node:assert/strict'
import { argumentHints, commandOf, completions, lineKind, nameOf, recall, remember } from './commandLine.js'
import { PLAYGROUND_FILTERS, PLAYGROUND_SLASH, isPlaygroundPath } from './playground.js'

const COMMANDS = [
  {
    name: 'ip',
    description: 'What is known of an IP address',
    arguments: [{ name: 'value', required: true }],
    group: 'Reputation',
  },
  {
    name: 'servicenow-create-incident',
    description: 'Open an incident.',
    needsConnection: true,
    arguments: [
      { name: 'short_description', type: 'text', required: true },
      { name: 'urgency', type: 'choice' },
      { name: 'description', type: 'text' },
    ],
  },
  {
    name: 'servicenow-get-incident',
    description: 'Read one.',
    needsConnection: true,
    arguments: [{ name: 'number', required: true }],
  },
  { name: 'ExtractDomains', description: 'Host names in a text', arguments: [{ name: 'text', required: true }] },
]

test('a line is a note, a slash command or a command', () => {
  assert.equal(lineKind('Called the user.'), 'note')
  assert.equal(lineKind('  /note x'), 'slash')
  assert.equal(lineKind('!ip 1.2.3.4'), 'command')
  assert.equal(lineKind(''), 'note')
  assert.deepEqual(nameOf('!serv'), { sign: '!', name: 'serv', done: false })
  assert.deepEqual(nameOf('!ip 1.2.3.4'), { sign: '!', name: 'ip', done: true })
  assert.deepEqual(nameOf('hello'), { sign: '', name: '', done: false })
})

test('the name of a command is completed while it is typed', () => {
  assert.deepEqual(
    completions(COMMANDS, '!serv').map((item) => item.value),
    ['!servicenow-create-incident ', '!servicenow-get-incident '],
  )
  // Those that start with what was typed first, then those that hold it.
  assert.deepEqual(
    completions(COMMANDS, '!i').map((item) => item.label),
    ['!ip', '!servicenow-create-incident', '!servicenow-get-incident', '!ExtractDomains'],
  )
  assert.equal(completions(COMMANDS, '!').length, 4)
  assert.equal(completions(COMMANDS, '!', 2).length, 2)
  assert.deepEqual(completions(COMMANDS, '!ip '), []) // the name is finished
  assert.deepEqual(completions(COMMANDS, 'a note'), [])
  assert.deepEqual(
    completions(COMMANDS, '/').map((item) => item.label),
    ['/note text', '/assign @user', '/close', '/task title @user due=2h'],
  )
  assert.deepEqual(
    completions(COMMANDS, '/a').map((item) => item.value),
    ['/assign '],
  )
  assert.deepEqual(completions(null, '!x'), [])
})

test('the arguments still to give are hinted, the required ones first', () => {
  assert.equal(commandOf(COMMANDS, '!IP 1.2.3.4').name, 'ip')
  assert.equal(commandOf(COMMANDS, '!ip'), null) // not finished yet
  assert.equal(commandOf(COMMANDS, '!nope x'), null)
  assert.deepEqual(
    argumentHints(COMMANDS, '!servicenow-create-incident ').map((hint) => hint.name),
    ['short_description', 'urgency', 'description', 'using'],
  )
  assert.deepEqual(
    argumentHints(COMMANDS, '!servicenow-create-incident urgency=1 using=Prod ').map((hint) => hint.name),
    ['short_description', 'description'],
  )
  assert.deepEqual(argumentHints(COMMANDS, '!ExtractDomains text="a b" '), [])
  assert.deepEqual(argumentHints(COMMANDS, 'a note'), [])
})

test('the lines typed before are walked with the arrows', () => {
  let history = remember([], '!ip 1.2.3.4')
  history = remember(history, '!ip 1.2.3.4') // the same again: once
  history = remember(history, '  ')
  history = remember(history, '/close')
  assert.deepEqual(history, ['!ip 1.2.3.4', '/close'])
  let state = recall(history, history.length, -1, 'draft')
  assert.deepEqual(state, { at: 1, text: '/close' })
  state = recall(history, state.at, -1, 'draft')
  assert.deepEqual(state, { at: 0, text: '!ip 1.2.3.4' })
  assert.deepEqual(recall(history, 0, -1, 'draft'), { at: 0, text: '!ip 1.2.3.4' }) // no further
  assert.deepEqual(recall(history, 1, 1, 'draft'), { at: 2, text: 'draft' }) // back to what was being written
  assert.equal(
    remember(
      Array.from({ length: 60 }, (_, index) => `l${index}`),
      'last',
    ).length,
    50,
  )
})

test('the Playground has an address, its own chips, and only the / line that needs no incident', () => {
  assert.equal(isPlaygroundPath('/playground'), true)
  assert.equal(isPlaygroundPath('/playground/'), true)
  assert.equal(isPlaygroundPath('/playground?x=1'), true)
  assert.equal(isPlaygroundPath('/playgrounds'), false)
  assert.equal(isPlaygroundPath('/incident/playground'), false)
  assert.equal(isPlaygroundPath(null), false)
  assert.deepEqual(
    PLAYGROUND_FILTERS.map((filter) => filter.id),
    ['all', 'notes', 'commands'],
  )
  // On an incident `/` offers every slash command the server reads (backend/app/commands.py SLASH);
  // in the Playground, the note alone.
  assert.deepEqual(
    completions([], '/').map((item) => item.value.trim()),
    ['/note', '/assign', '/close', '/task'],
  )
  assert.deepEqual(
    completions([], '/', 8, PLAYGROUND_SLASH).map((item) => item.value),
    ['/note '],
  )
  assert.deepEqual(completions([], '/cl', 8, PLAYGROUND_SLASH), [])
})
