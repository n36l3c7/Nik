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
