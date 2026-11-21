import test from 'node:test'
import assert from 'node:assert/strict'
import {
  changesOf,
  choiceValue,
  doorWords,
  formOf,
  foundPath,
  instanceChoice,
  onlyFound,
  problemsOf,
  scanWords,
  skipLines,
} from './indicatorsFound.js'

const SETTINGS = {
  enabled: true,
  types: ['ip', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256'],
  allTypes: ['ip', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256'],
  leaveOutPrivate: true,
  leaveOutBenign: true,
  cap: 50,
  capMax: 500,
  skip: ['*id', 'context.Ticket.URL'],
  lookUps: false,
  instances: {},
}

test('the form of the setting, and what it changes', () => {
  const form = formOf(SETTINGS)
  assert.deepEqual(form, {
    enabled: true,
    types: SETTINGS.types,
    leaveOutPrivate: true,
    leaveOutBenign: true,
    cap: '50',
    skip: '*id\ncontext.Ticket.URL',
    lookUps: false,
  })
  assert.deepEqual(changesOf(form, SETTINGS), {})
  const edited = {
    ...form,
    enabled: false,
    types: ['url', 'ip'],
    cap: '20',
    skip: '*id\n\n  context.Ticket.URL  \nconsole*\n*id',
    lookUps: true,
  }
  // The types come out in the order the server lists them; the paths without blanks and repeats.
  assert.deepEqual(changesOf(edited, SETTINGS), {
    enabled: false,
    lookUps: true,
    types: ['ip', 'url'],
    cap: 20,
    skip: ['*id', 'context.Ticket.URL', 'console*'],
  })
  assert.deepEqual(skipLines(' a \n\nb\na'), ['a', 'b'])
})

test('what the form cannot be saved with', () => {
  const form = formOf(SETTINGS)
  assert.deepEqual(problemsOf(form, SETTINGS), {})
  for (const cap of ['', '0', '501', '1.5', 'many', '-3']) {
    assert.equal(problemsOf({ ...form, cap }, SETTINGS).cap, 'A whole number from 1 to 500', cap)
  }
  assert.match(problemsOf({ ...form, skip: 'two words' }, SETTINGS).skip, /^"two words" is not a path/)
  assert.equal(
    problemsOf({ ...form, skip: Array.from({ length: 101 }, (_, i) => `k${i}`).join('\n') }, SETTINGS).skip,
    'A hundred paths at most',
  )
  assert.match(problemsOf({ ...form, types: [] }, SETTINGS).types, /^With no type chosen/)
  // Turned off, no type chosen is nothing to complain of.
  assert.deepEqual(problemsOf({ ...form, enabled: false, types: [] }, SETTINGS), {})
})

test('a found indicator says where it was read, and what holds it only for that', () => {
  assert.equal(foundPath('found:context.URL[0].Data'), 'context.URL[0].Data')
  assert.equal(foundPath('warroom'), null)
  assert.equal(onlyFound(['found:incident.name']), true)
  assert.equal(onlyFound(['found:incident.name', 'mail:invoice.eml']), false)
  assert.equal(onlyFound([]), false)
})

test('the last reading in a sentence', () => {
  assert.equal(
    scanWords(null, true),
    'This incident was never read for indicators: it came in before incidents were read.',
  )
  assert.equal(scanWords(null, false), 'Incidents from where this one came are not read for indicators.')
  assert.equal(
    scanWords({ door: 'fetch', kept: 6, leftOut: {}, over: 0 }, true),
    'Last read when it was fetched: 6 kept.',
  )
  assert.equal(
    scanWords(
      { door: 'mirror', kept: 50, leftOut: { private: 3, benign: 4 }, over: 12, cap: 50, removed: 1, unread: 2 },
      true,
    ),
    'Last read at an update from the other system: 50 kept, 7 left out as private or harmless, ' +
      '12 over the limit of 50 and not kept, 1 removed by a person and not found again, 2 values not read.',
  )
  assert.equal(doorWords('asked'), 'when someone asked')
  assert.equal(doorWords('nope'), '')
})

test('what an instance says of its own incidents', () => {
  assert.deepEqual([true, false, null, undefined].map(instanceChoice), ['on', 'off', 'setting', 'setting'])
  assert.deepEqual(['on', 'off', 'setting'].map(choiceValue), [true, false, null])
})
