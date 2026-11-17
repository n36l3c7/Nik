import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { MESSAGES, parse, tryParse } from './parse.js'
import { tokenAt, tokenize } from './tokenize.js'
import { applyCompletion, completions, fieldOf, writeValue } from './complete.js'
import { conditionOn, isComplete, opLabel, opsFor, toModel, toText, withCondition } from './builder.js'

// The parser's vectors, shared with the backend (tests/test_query.py reads the same file).
const { vectors } = JSON.parse(
  readFileSync(new URL('../../../../backend/tests/data/query_vectors.json', import.meta.url), 'utf8'),
)

const SCHEMA = {
  entity: 'incidents',
  fields: [
    { name: 'name', aliases: [], kind: 'text', values: [], description: 'The name shown in the list' },
    { name: 'severity', aliases: [], kind: 'ordered', values: ['low', 'medium', 'high', 'critical'], description: '' },
    { name: 'status', aliases: [], kind: 'keyword', values: ['open', 'in_progress', 'closed'], description: '' },
    { name: 'owner', aliases: ['assignee'], kind: 'keyword', values: [], description: 'Who has the incident' },
    { name: 'hasMail', aliases: ['mail'], kind: 'bool', values: [], description: '' },
    { name: 'created', aliases: ['createdAt'], kind: 'date', values: [], description: 'When it was created' },
    { name: 'score', aliases: [], kind: 'number', values: [], description: '' },
    { name: 'tags', aliases: ['tag'], kind: 'tags', values: [], description: '' },
  ],
}

test('the parser reads the vectors it shares with the backend', () => {
  assert.ok(vectors.length > 60)
  for (const vector of vectors) {
    const label = JSON.stringify(vector.query.slice(0, 60))
    if (vector.error) {
      assert.throws(
        () => parse(vector.query),
        (error) => error.code === vector.error.code && error.position === vector.error.position,
        label,
      )
    } else {
      assert.deepEqual(parse(vector.query), vector.tree, label)
    }
  }
  // Every error has its sentence, the same the server uses.
  const codes = new Set(vectors.filter((vector) => vector.error).map((vector) => vector.error.code))
  assert.deepEqual([...codes].sort(), Object.keys(MESSAGES).sort())
  assert.deepEqual(tryParse('status:'), {
    tree: null,
    error: { code: 'missing_value', position: 7, message: 'A value is expected after the colon' },
  })
  assert.deepEqual(tryParse('  '), { tree: null, error: null })
})

test('whatever is typed is cut into tokens that cover it, half-written or wrong', () => {
  const types = (text) => tokenize(text).map((token) => `${token.type}:${token.text}`)
  assert.deepEqual(types('status:open and -owner:"" (a or b)'), [
    'field:status',
    'op::',
    'value:open',
    'space: ',
    'keyword:and',
    'space: ',
    'not:-',
    'field:owner',
    'op::',
    'value:""',
    'space: ',
    'paren:(',
    'text:a',
    'space: ',
    'keyword:or',
    'space: ',
    'text:b',
    'paren:)',
  ])
  assert.deepEqual(types('created:>="7 days ago" score:[1 TO 5]'), [
    'field:created',
    'op::>=',
    'value:"7 days ago"',
    'space: ',
    'field:score',
    'op::',
    'range:[1 TO 5]',
  ])
  assert.deepEqual(types('"two words" name:foo(bar)'), [
    'quote:"two words"',
    'space: ',
    'field:name',
    'op::',
    'value:foo(bar)',
  ])
  // Half-written and wrong input: no gap, no overlap, no exception.
  for (const text of [
    'status:',
    'name:"open',
    '((a',
    'a))',
    'score:[1 TO',
    '-',
    'not',
    'x:>',
    ' ',
    '',
    'C:\\Users\\a b',
    '"',
  ]) {
    const tokens = tokenize(text)
    assert.equal(tokens.map((token) => token.text).join(''), text, JSON.stringify(text))
    let at = 0
    for (const token of tokens) {
      assert.equal(token.start, at)
      assert.ok(token.end > token.start)
      at = token.end
    }
  }
  const tokens = tokenize('status:op name')
  assert.equal(tokenAt(tokens, 9).type, 'value')
  assert.equal(tokenAt(tokens, 7).type, 'op')
  assert.equal(tokenAt(tokens, 10), null) // right after the space
  assert.equal(tokenAt(tokens, 14).text, 'name')
})

test('fields are offered at the start of a condition, values after the colon', () => {
  const labels = (text, caret = text.length, options) =>
    completions(text, caret, SCHEMA, options)?.items.map((item) => item.label) ?? null

  assert.deepEqual(labels('s'), ['severity', 'status', 'score', 'hasMail', 'tags'])
  assert.deepEqual(labels('st'), ['status'])
  assert.deepEqual(labels('ass'), ['assignee']) // another name of owner
  assert.deepEqual(labels('status:open own'), ['owner'])
  assert.equal(labels(''), null) // nothing typed: nothing in the way
  assert.equal(labels('', 0, { force: true }).length, 8) // asked for: every field
  assert.equal(labels('zzz'), null)
  assert.equal(labels('status', 3), null) // the caret is inside the word

  assert.deepEqual(labels('status:'), ['open', 'in_progress', 'closed'])
  assert.deepEqual(labels('status:c'), ['closed'])
  assert.deepEqual(labels('status:>=o'), ['open', 'in_progress', 'closed']) // what starts with it first
  assert.deepEqual(labels('severity:>='), ['low', 'medium', 'high', 'critical'])
  assert.deepEqual(labels('assignee:'), null) // a free value: nothing to list
  assert.deepEqual(labels('hasMail:'), ['true', 'false'])
  assert.deepEqual(labels('created:>='), ['today', 'yesterday', 'now-24h', 'now-7d', 'now-30d'])
  assert.equal(labels('status:open'), null) // already a value: nothing more to say
  assert.equal(labels('nope:'), null)
  assert.equal(completions('st', 2, null), null)

  // Taking an item: a field stays open for its value, a value is followed by a space.
  let found = completions('status:open st', 14, SCHEMA)
  assert.deepEqual(applyCompletion('status:open st', found, found.items[0]), { text: 'status:open status:', caret: 19 })
  found = completions('status:c', 8, SCHEMA)
  assert.deepEqual(applyCompletion('status:c', found, found.items[0]), { text: 'status:closed ', caret: 14 })
  found = completions('status:c name:x', 8, SCHEMA)
  assert.deepEqual(applyCompletion('status:c name:x', found, found.items[0]), {
    text: 'status:closed name:x',
    caret: 13,
  })

  assert.equal(fieldOf(SCHEMA, 'ASSIGNEE').name, 'owner')
  assert.equal(fieldOf(SCHEMA, 'nope'), null)
  assert.equal(writeValue('open'), 'open')
  assert.equal(writeValue('two words'), '"two words"')
  assert.equal(writeValue('a"b\\c'), '"a\\"b\\\\c"')
  assert.equal(writeValue(''), '""')
})

test('the builder shows a query it can represent, and writes back the same query', () => {
  const round = (text) => {
    const model = toModel(text)
    return model && toText(model)
  }
  // What it shows comes back as it was (in its canonical writing).
  for (const text of [
    'status:open',
    'status:open severity:>=high',
    'status:open or status:closed',
    'status:open (severity:high or severity:critical) owner:""',
    '(status:open name:wks-*) or score:[10 TO 50]',
    'evil -kit',
    'owner:* name:!x',
    'created:>=now-7d created:[2026-11-01 TO *]',
    'name:"two words" "free text"',
    'tags:!phish',
  ]) {
    assert.equal(round(text), text, text)
  }
  assert.equal(round('status:open and severity:high'), 'status:open severity:high')
  assert.equal(round('not status:open'), 'status:!open')
  assert.equal(round('owner:* -name:x'), 'owner:* name:!x')
  assert.equal(round('-owner:*'), 'owner:""')
  assert.equal(round('owner:!""'), 'owner:*')
  assert.equal(round('-name:!x'), 'name:x')
  assert.equal(round(''), '')

  assert.deepEqual(toModel('status:open -evil score:[1 TO *]'), {
    join: 'and',
    rows: [
      { field: 'status', op: '=', value: 'open', value2: '' },
      { field: '', op: '!', value: 'evil', value2: '' },
      { field: 'score', op: 'between', value: '1', value2: '' },
    ],
  })
  assert.deepEqual(toModel('a or (b c)'), {
    join: 'or',
    rows: [
      { field: '', op: '=', value: 'a', value2: '' },
      {
        join: 'and',
        rows: [
          { field: '', op: '=', value: 'b', value2: '' },
          { field: '', op: '=', value: 'c', value2: '' },
        ],
      },
    ],
  })

  // What it cannot show: "edit as text".
  for (const text of [
    'a or (b (c or d))', // two levels of groups
    '-(a or b)', // a negated group
    'not not a',
    '-score:>5', // a negated comparison
    '-score:[1 TO 2]',
    'name:"a*b"', // a star that is not a wildcard
    'status:', // cannot be read
    '(a',
  ]) {
    assert.equal(toModel(text), null, text)
  }

  // Rows that say nothing yet are left out of the text.
  assert.equal(isComplete({ field: 'status', op: '=', value: '', value2: '' }), false)
  assert.equal(isComplete({ field: 'owner', op: 'empty', value: '', value2: '' }), true)
  assert.equal(isComplete({ field: '', op: 'filled', value: '', value2: '' }), false)
  assert.equal(
    toText({
      join: 'and',
      rows: [
        { field: 'status', op: '=', value: '', value2: '' },
        { field: 'name', op: '=', value: 'two words', value2: '' },
        { join: 'or', rows: [{ field: 'score', op: '>', value: '5', value2: '' }] },
        { join: 'or', rows: [{ field: '', op: '=', value: '', value2: '' }] },
      ],
    }),
    'name:"two words" score:>5',
  )

  // The operators a kind of field takes.
  const ids = (kind) => opsFor(kind).map((op) => op.id)
  assert.deepEqual(ids(''), ['=', '!'])
  assert.deepEqual(ids('text'), ['=', '!', 'empty', 'filled'])
  assert.deepEqual(ids('bool'), ['=', '!'])
  assert.deepEqual(ids('number'), ['=', '!', '>', '>=', '<', '<=', 'between', 'empty', 'filled'])
  assert.equal(opLabel(opsFor('text')[0], 'text'), 'contains')
  assert.equal(opLabel(opsFor('keyword')[0], 'keyword'), 'is')
  assert.equal(opLabel(opsFor('tags')[1], 'tags'), 'has not')
})

test('a filter writes its condition into the query, and reads it back', () => {
  assert.equal(conditionOn('status:open name:x', 'status', SCHEMA), 'status:open')
  assert.equal(conditionOn('name:x assignee:anna', 'owner', SCHEMA), 'assignee:anna') // by its other name too
  assert.equal(conditionOn('name:x', 'status', SCHEMA), '')
  assert.equal(conditionOn('', 'status', SCHEMA), '')
  assert.equal(conditionOn('status:open or name:x', 'status', SCHEMA), '') // not at the top level
  assert.equal(conditionOn('(status:open', 'status', SCHEMA), null) // cannot be read

  assert.equal(withCondition('', 'status', 'status:open', SCHEMA), 'status:open')
  assert.equal(withCondition('name:x', 'status', 'status:open', SCHEMA), 'name:x status:open')
  assert.equal(withCondition('status:closed name:x', 'status', 'status:open', SCHEMA), 'name:x status:open')
  assert.equal(withCondition('status:closed name:x', 'status', '', SCHEMA), 'name:x')
  assert.equal(withCondition('assignee:bob', 'owner', 'owner:anna', SCHEMA), 'owner:anna')
  assert.equal(withCondition('status:open', 'status', '', SCHEMA), '')
  // A query the builder does not rewrite is kept as written, and the condition added to the whole.
  assert.equal(withCondition('a or b', 'status', 'status:open', SCHEMA), '(a or b) status:open')
  assert.equal(withCondition('-(a or b)', 'status', 'status:open', SCHEMA), '(-(a or b)) status:open')
  assert.equal(withCondition('a or b', 'status', '', SCHEMA), 'a or b')
  assert.equal(
    conditionOn(withCondition('x', 'severity', 'severity:>=high', SCHEMA), 'severity', SCHEMA),
    'severity:>=high',
  )
})
