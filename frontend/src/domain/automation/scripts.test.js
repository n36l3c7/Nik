import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  diffCounts,
  draftOf,
  draftProblems,
  fieldProblems,
  lineDiff,
  nameProblem,
  parseJson,
  sameDraft,
} from './scripts.js'

test('a script is named like its node: a capital letter, letters and digits', () => {
  assert.equal(nameProblem('GroupByField'), null)
  assert.equal(nameProblem(''), 'A name is needed')
  assert.match(nameProblem('groupByField'), /capital letter/)
  assert.match(nameProblem('Group by field'), /capital letter/)
  assert.match(nameProblem('Ab'), /capital letter/)
})

test('the editor starts from the draft, else from the current version', () => {
  const current = {
    code: 'def main(args):\n    return 1\n',
    arguments: [{ name: 'a' }],
    outputs: [],
    test: { args: { a: 1 } },
  }
  assert.equal(draftOf({ current, draft: null }).code, current.code)
  assert.equal(draftOf({ current, draft: { code: 'x' } }).code, 'x')
  assert.deepEqual(draftOf({ current, draft: { code: 'x' } }).test, { args: {} })
  assert.deepEqual(draftOf(null), { code: '', arguments: [], outputs: [], test: { args: {} } })
  assert.deepEqual(draftOf({ draft: { code: 'x', test: { args: { n: 1 }, expect: null } } }).test, {
    args: { n: 1 },
    expect: null,
  })
  assert.ok(sameDraft(draftOf({ current }), current))
  assert.ok(!sameDraft(draftOf({ current }), { ...current, code: `${current.code}\n` }))
  assert.ok(
    sameDraft(
      { code: 'x', arguments: [{ name: 'a' }] },
      { code: 'x', arguments: [{ name: 'a', type: 'any', required: false }] },
    ),
  )
})

test('arguments and outputs need valid, distinct names', () => {
  assert.deepEqual(fieldProblems([{ name: 'items' }, { name: 'field' }]), [])
  assert.deepEqual(fieldProblems([{ name: 'Items' }, { name: 'a' }, { name: 'a' }]), [
    { index: 0, message: 'A lower-case letter, then letters, digits or _' },
    { index: 2, message: 'Two are called "a"' },
  ])
  assert.deepEqual(fieldProblems(null), [])
})

test('JSON typed in a box is read, or says why not', () => {
  assert.deepEqual(parseJson(' {"a": [1, 2]} '), { value: { a: [1, 2] } })
  assert.deepEqual(parseJson('', {}), { value: {} })
  assert.match(parseJson('{a: 1}').error, /^Not JSON: /)
})

test('what keeps a draft from being tested', () => {
  const good = { code: 'def main(args):\n    return {}\n', arguments: [], outputs: [], test: { args: {} } }
  assert.deepEqual(draftProblems(good), [])
  assert.deepEqual(draftProblems({ ...good, code: '  ' }), ['The script has no code'])
  assert.deepEqual(draftProblems({ ...good, code: 'print(1)' }), ['The code needs a function: def main(args)'])
  assert.deepEqual(draftProblems({ ...good, arguments: [{ name: '9' }], test: { args: [] } }), [
    'An argument has no valid name',
    'The arguments of the test are an object: {"name": value}',
  ])
})

test('the diff of two versions of the code, line by line', () => {
  const before = 'def main(args):\n    groups = {}\n    return groups\n'
  const after = 'def main(args):\n    groups = {}\n    count = 0\n    return {"groups": groups}\n'
  const diff = lineDiff(before, after)
  assert.deepEqual(
    diff.map((line) => `${{ same: ' ', add: '+', remove: '-' }[line.kind]}${line.text}`),
    [
      'def main(args):',
      '    groups = {}',
      '-    return groups',
      '+    count = 0',
      '+    return {"groups": groups}',
      '',
    ].map((line, index) => ([0, 1, 5].includes(index) ? ` ${line}` : line)),
  )
  assert.deepEqual(diffCounts(diff), { added: 2, removed: 1 })
  assert.deepEqual(diffCounts(lineDiff('same\n', 'same\n')), { added: 0, removed: 0 })
  assert.deepEqual(lineDiff('', 'a'), [
    { kind: 'remove', text: '' },
    { kind: 'add', text: 'a' },
  ])
  // Too long to compare: both whole.
  const long = Array.from({ length: 2001 }, (_, index) => `line ${index}`).join('\n')
  assert.equal(lineDiff(long, 'x').filter((line) => line.kind === 'same').length, 0)
})
