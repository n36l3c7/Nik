import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import {
  ExpressionError,
  FILTER_NAMES,
  FUNCTION_NAMES,
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
  assert.ok(vectors.length > 200)
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
  // Wherever the name is read: in a condition, in the argument of a filter, in a list.
  assert.equal(
    renameRoot("{{ if(search.count > 1, a.x | default(search.first), [search.last, 'search']) }}", 'search', 's2'),
    "{{ if(s2.count > 1, a.x | default(s2.first), [s2.last, 'search']) }}",
  )
})

test('an expression that decides or counts is read, and every path in it is a reference', () => {
  for (const valid of [
    "{{ if(data.stats.malicious >= 3, 'malicious', 'unknown') }}",
    "{{ now.iso | date_diff(data.registered, 'days') < 30 }}",
    "{{ data.tags | has_any(['c2', 'tor']) and not data.zero }}",
    '{{ (a.b + 1) * 2 / c | round(1) }}',
    "{{ first_of(a.b, c.d, 'none') ~ ' ' ~ (n | plural('report')) }}",
  ]) {
    assert.equal(problemOf(valid), null, valid)
  }
  assert.deepEqual(problemOf('{{ nope(1) }}'), { position: 3, message: 'There is no function "nope"' })
  assert.deepEqual(problemOf('{{ 1 + }}'), { position: 7, message: 'A name is expected here' })
  assert.deepEqual(
    references('{{ if(search.count > index, trigger.mail.urls | limit(run.id | length), [item.name]) }}')
      .map((found) => found.name)
      .sort(),
    ['index', 'item', 'run', 'search', 'trigger'],
  )
  // One path is still said as one path; something computed names none.
  const [one] = parse('{{ trigger.mail.subject | upper }}')
  assert.deepEqual(
    [one.root, one.steps, one.filters.map((filter) => filter.name)],
    ['trigger', ['mail', 'subject'], ['upper']],
  )
  assert.equal(parse('{{ 1 + search.count }}')[0].root, '')
  assert.deepEqual(FUNCTION_NAMES, ['if', 'first_of', 'min', 'max'])
  assert.ok(['round', 'plural', 'date_diff', 'has_any', 'sha256'].every((name) => FILTER_NAMES.includes(name)))
  // The side that does not count is not read, and the bounds are the server's.
  assert.equal(renderText("{{ if(trigger.mail.flag, 'yes', trigger.mail.gone) }}", scope), 'yes')
  assert.equal(renderText('n={{ 6 / 3 }}', scope), 'n=2')
  assert.throws(() => parse(`{{ ${Array(200).fill('1').join(' + ')} }}`), /too long/)
  assert.throws(() => parse(`{{ ${'['.repeat(41)}${']'.repeat(41)} }}`), /too deep/)
  assert.throws(() => renderText('{{ 999999999999 * 999999999999 }}', scope), /too large/)
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
