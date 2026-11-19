import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import {
  ExpressionError,
  compare,
  lookup,
  MISSING,
  parse,
  problemOf,
  references,
  renameRoot,
  render,
  renderText,
} from './expressions.js'

// The vectors the server's parser reads too (backend/tests/test_automation_graph.py).
const { scope, vectors } = JSON.parse(
  readFileSync(new URL('../../../../backend/tests/data/expressions.json', import.meta.url), 'utf8'),
)

test('expressions give what the vectors shared with the server say', () => {
  assert.ok(vectors.length > 70)
  for (const vector of vectors) {
    if (vector.error) {
      assert.throws(
        () => renderText(vector.template, scope),
        (error) => {
          assert.ok(error instanceof ExpressionError, vector.template)
          assert.equal(error.position, vector.error.position, vector.template)
          assert.equal(error.message, vector.message, vector.template)
          return true
        },
      )
    } else {
      assert.deepEqual(renderText(vector.template, scope), vector.result, vector.template)
    }
  }
})

test('one expression alone keeps its type; a structure is rendered through', () => {
  assert.equal(renderText('{{ trigger.mail.score }}', scope), 82)
  assert.equal(renderText(' {{ trigger.mail.score }}', scope), ' 82')
  const config = {
    to: ['{{ trigger.mail.sender }}', 7],
    n: '{{ search.count }}',
    keep: null,
    deep: { x: 'a{{ index }}' },
  }
  assert.deepEqual(render(config, scope), { to: ['Eve <eve@evil.example>', 7], n: 3, keep: null, deep: { x: 'a2' } })
  assert.deepEqual(
    references(config)
      .map((found) => `${found.name}@${found.position}`)
      .sort(),
    ['index@1', 'search@0', 'trigger@0'],
  )
  assert.deepEqual(references('no braces'), [])
  assert.deepEqual(references(12), [])
})

test('what is wrong with a text is said with its position, without throwing', () => {
  assert.equal(problemOf('plain'), null)
  assert.equal(problemOf('{{ trigger.mail.subject }}'), null)
  assert.deepEqual(problemOf('a {{ trigger.mail.subject }'), { position: 26, message: '}} is expected here' })
  assert.throws(() => parse('x'.repeat(20_001)), ExpressionError)
  assert.throws(() => parse('{{ a }}'.repeat(201)), ExpressionError)
})

test('renaming a node rewrites the expressions that read it, and only those', () => {
  const config = {
    text: 'Found {{ search.count }} and {{ searching.count }} by {{search | length}}',
    list: ['{{ search }}', 3],
    broken: '{{ search.',
  }
  assert.deepEqual(renameRoot(config, 'search', 'lookup_2'), {
    text: 'Found {{ lookup_2.count }} and {{ searching.count }} by {{lookup_2 | length}}',
    list: ['{{ lookup_2 }}', 3],
    broken: '{{ search.',
  })
})

test('comparisons and lookups behave as on the server', () => {
  assert.equal(lookup({ a: [{ b: 1 }] }, 'a.0.b'), 1)
  assert.equal(lookup({ a: [1, 2] }, 'a.-1'), 2)
  assert.equal(lookup({ a: 1 }, 'b'), MISSING)
  assert.ok(compare('Rome', 'eq', 'rome'))
  assert.ok(compare('82', 'eq', 82))
  assert.ok(compare(82, 'gte', '70'))
  assert.ok(compare('b', 'gt', 'a'))
  assert.ok(compare(['a', 'B'], 'contains', 'b'))
  assert.ok(compare('phishing', 'in', ['spam', 'Phishing']))
  assert.ok(compare(MISSING, 'empty'))
  assert.ok(!compare(MISSING, 'exists'))
  assert.ok(compare({ a: 1 }, 'eq', { a: 1 }))
  assert.ok(!compare({ a: 1 }, 'eq', '{"a":1}'))
})

test('what is typed between braces is completed from the values a node can read', async () => {
  const { complete, completions, typedAt } = await import('./expressions.js')
  // The path at the caret, while its braces are open.
  assert.deepEqual(typedAt('Seen on {{ incident.ho', 22), { start: 8, typed: 'incident.ho' })
  assert.deepEqual(typedAt('{{', 2), { start: 0, typed: '' })
  assert.deepEqual(typedAt('{{ made.lists[0].na', 19), { start: 0, typed: 'made.lists[0].na' })
  assert.deepEqual(typedAt('{{ a }} and {{ b', 16), { start: 12, typed: 'b' })
  // Outside braces, after they close, and past the path (a filter is being typed): nothing.
  assert.equal(typedAt('plain text', 5), null)
  assert.equal(typedAt('{{ a }} and', 11), null)
  assert.equal(typedAt('{{ a | up', 9), null)
  assert.equal(typedAt('{{ a b', 6), null)

  const tree = [
    {
      name: 'made',
      label: 'Create an incident',
      fields: [
        { path: 'made.incident', type: 'object', description: 'The incident' },
        { path: 'made.incident.id', type: 'text', description: 'Its id' },
        { path: 'made.incident.name', type: 'text' },
      ],
    },
    { name: 'incident', label: 'The incident, now', fields: [{ path: 'incident.id', type: 'text' }] },
  ]
  const paths = (typed, limit) => completions(tree, typed, limit).map((entry) => entry.path)
  assert.deepEqual(paths(''), ['made.incident', 'made.incident.id', 'made.incident.name', 'incident.id'])
  // What starts with it first, then what holds it; the object itself stays among them.
  assert.deepEqual(paths('incident.'), ['incident.id', 'made.incident.id', 'made.incident.name'])
  assert.deepEqual(paths('made.incident'), ['made.incident', 'made.incident.id', 'made.incident.name'])
  assert.deepEqual(paths('MADE.INCIDENT.N'), ['made.incident.name'])
  assert.deepEqual(paths('nothing'), [])
  assert.deepEqual(paths('', 2), ['made.incident', 'made.incident.id'])
  assert.deepEqual(completions(tree, 'made.incident.id')[0], {
    path: 'made.incident.id',
    type: 'text',
    description: 'Its id',
    label: 'Create an incident',
  })
  assert.deepEqual(completions(null, ''), [])

  // The choice replaces what was typed, braces included, and the caret goes after it.
  assert.deepEqual(complete('Seen on {{ incident.ho', 22, 'incident.host'), {
    text: 'Seen on {{ incident.host }}',
    caret: 27,
  })
  // Braces that already close it are not written twice, and what follows is kept.
  assert.deepEqual(complete('{{ inc }} later', 6, 'incident.id'), { text: '{{ incident.id }} later', caret: 17 })
  assert.deepEqual(complete('a {{ b }} {{', 12, 'run.id'), { text: 'a {{ b }} {{ run.id }}', caret: 22 })
})
