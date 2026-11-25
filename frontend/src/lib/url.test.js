import test from 'node:test'
import assert from 'node:assert/strict'
import { extractDomain, truncate } from './url.js'

test('the domain of a URL has no www, and a string that is no URL has none', () => {
  assert.equal(extractDomain('https://www.example.com/a?b=1'), 'example.com')
  assert.equal(extractDomain('not a url'), null)
})

test('a long text is cut with an ellipsis', () => {
  assert.equal(truncate('abcdef', 4), 'abc…')
  assert.equal(truncate('abc', 4), 'abc')
  assert.equal(truncate(''), '')
})
