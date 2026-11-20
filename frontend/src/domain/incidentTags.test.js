import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  TAGS_MAX,
  TAG_RULE,
  addTag,
  cleanTag,
  fitTags,
  removeTag,
  suggestTags,
  tagCondition,
  tagField,
  tagsInQuery,
  tagsInUse,
  toggleTag,
  withTag,
  withoutTag,
  withoutTags,
} from './incidentTags.js'

const SCHEMA = {
  entity: 'incidents',
  fields: [
    { name: 'name', aliases: [], kind: 'text', values: [] },
    { name: 'status', aliases: [], kind: 'keyword', values: ['open', 'in_progress', 'closed'] },
    { name: 'labels', aliases: ['tag', 'tags'], kind: 'tags', values: [] },
  ],
}
// An installation that had a field called "tags" before the incidents had tags: it keeps the name.
const TAKEN = {
  entity: 'incidents',
  fields: [
    { name: 'labels', aliases: [], kind: 'tags', values: [] },
    { name: 'tag', aliases: ['field.tag'], kind: 'text', values: [], custom: true },
  ],
}

test('a tag is lower case, one word, of the characters a tag of an indicator takes', () => {
  assert.deepEqual(cleanTag('  Phish '), { tag: 'phish', error: null })
  assert.deepEqual(cleanTag('#Campaign:Q4'), { tag: 'campaign:q4', error: null })
  assert.deepEqual(cleanTag('data   leak'), { tag: 'data-leak', error: null })
  assert.deepEqual(cleanTag('a'.repeat(40)), { tag: 'a'.repeat(40), error: null })
  assert.deepEqual(cleanTag(''), { tag: '', error: null })
  assert.deepEqual(cleanTag('   '), { tag: '', error: null })
  for (const wrong of ['-x', 'a'.repeat(41), 'né', 'a,b', 'a/b', '#']) {
    assert.deepEqual(cleanTag(wrong), wrong === '#' ? { tag: '', error: null } : { tag: '', error: TAG_RULE }, wrong)
  }
})

test('a tag is added once, at the end, and twelve are the most', () => {
  const held = ['phish', 'vip']
  assert.deepEqual(addTag(held, 'Wire Fraud'), { tags: ['phish', 'vip', 'wire-fraud'], error: null })
  // The one it has already, however it is written: the same list, so nothing is saved.
  assert.equal(addTag(held, '#PHISH').tags, held)
  assert.equal(addTag(held, '  ').tags, held)
  assert.deepEqual(addTag(held, 'no/slash'), { tags: held, error: TAG_RULE })
  assert.deepEqual(addTag(undefined, 'first'), { tags: ['first'], error: null })
  const full = Array.from({ length: TAGS_MAX }, (_, index) => `t${index}`)
  assert.deepEqual(addTag(full, 'more'), { tags: full, error: 'An incident holds 12 tags at most.' })
  assert.equal(addTag(full, 't3').error, null)

  assert.deepEqual(removeTag(['Phish', 'vip'], 'phish'), ['vip'])
  assert.deepEqual(removeTag(['phish'], 'other'), ['phish'])
  assert.deepEqual(removeTag(null, 'x'), [])
})

test('the tags in use are counted over the incidents, the most used first', () => {
  const rows = [
    { id: 'a', tags: ['phish', 'vip'] },
    { id: 'b', tags: ['Phish', 'wire'] },
    { id: 'c', tags: ['phish', 'phish', 'acme'] },
    { id: 'd', tags: [] },
    { id: 'e' },
  ]
  assert.deepEqual(tagsInUse(rows), [
    { tag: 'phish', count: 3 },
    { tag: 'acme', count: 1 },
    { tag: 'vip', count: 1 },
    { tag: 'wire', count: 1 },
  ])
  assert.deepEqual(tagsInUse(null), [])
})

test('what is offered while a tag is typed: the tags in use the incident does not have', () => {
  const inUse = [
    { tag: 'phish', count: 3 },
    { tag: 'spear-phish', count: 2 },
    { tag: 'vip', count: 1 },
    { tag: 'wire', count: 1 },
  ]
  assert.deepEqual(suggestTags(inUse, [], ''), ['phish', 'spear-phish', 'vip', 'wire'])
  assert.deepEqual(suggestTags(inUse, ['VIP'], ''), ['phish', 'spear-phish', 'wire'])
  assert.deepEqual(suggestTags(inUse, [], 'Phi'), ['phish', 'spear-phish'])
  assert.deepEqual(suggestTags(inUse, ['phish'], '#phi'), ['spear-phish'])
  assert.deepEqual(suggestTags(inUse, [], 'zzz'), [])
  assert.deepEqual(suggestTags(inUse, [], '', 2), ['phish', 'spear-phish'])
})

test('a cell shows the tags it has room for, and counts the others', () => {
  assert.deepEqual(fitTags(['phish', 'vip']), { shown: ['phish', 'vip'], more: 0 })
  assert.deepEqual(fitTags(['a', 'b', 'c', 'd', 'e']), { shown: ['a', 'b', 'c'], more: 2 })
  assert.deepEqual(fitTags(['a-rather-long-tag-of-thirty-chars', 'vip']), {
    shown: ['a-rather-long-tag-of-thirty-chars'],
    more: 1,
  })
  assert.deepEqual(fitTags(['customer-acme', 'campaign:q4-2026', 'vip']), {
    shown: ['customer-acme'],
    more: 2,
  })
  assert.deepEqual(fitTags([]), { shown: [], more: 0 })
  assert.deepEqual(fitTags(undefined), { shown: [], more: 0 })
})

test('a tag is asked as tag:, and as labels: where a field of the installation is called tag', () => {
  assert.equal(tagField(SCHEMA), 'tag')
  assert.equal(tagField(null), 'tag')
  assert.equal(tagField(TAKEN), 'labels')
  assert.equal(tagCondition('phish', SCHEMA), 'tag:phish')
  assert.equal(tagCondition('campaign:q4', SCHEMA), 'tag:campaign:q4')
  assert.equal(tagCondition('Suspicious Login', SCHEMA), 'tag:"Suspicious Login"')
  assert.equal(tagCondition('phish', TAKEN), 'labels:phish')
})

test('the tags a query asks for are read by every name of the field', () => {
  assert.deepEqual(tagsInQuery('', SCHEMA), [])
  assert.deepEqual(tagsInQuery('status:open tag:phish TAGS:vip labels:"old one"', SCHEMA), ['phish', 'vip', 'old one'])
  assert.deepEqual(tagsInQuery('tag:campaign:q4', SCHEMA), ['campaign:q4'])
  // "Has not", "holds something" and alternatives are not tags that are asked for.
  assert.deepEqual(tagsInQuery('!tag:phish tag:* tag:""', SCHEMA), [])
  assert.deepEqual(tagsInQuery('tag:phish or tag:vip', SCHEMA), [])
  assert.deepEqual(tagsInQuery('status:open (tag:a or tag:b)', SCHEMA), [])
  assert.equal(tagsInQuery('tag:"unclosed', SCHEMA), null)
  // Without the schema the names every installation has are read.
  assert.deepEqual(tagsInQuery('tag:phish labels:vip'), ['phish', 'vip'])
  assert.deepEqual(tagsInQuery('tag:mine labels:phish', TAKEN), ['phish'])
})

test('several tags narrow the list: each one chosen is one more condition', () => {
  assert.equal(withTag('', 'phish', SCHEMA), 'tag:phish')
  assert.equal(withTag('status:open', 'phish', SCHEMA), 'status:open tag:phish')
  assert.equal(withTag('status:open tag:phish', 'vip', SCHEMA), 'status:open tag:phish tag:vip')
  // Asked already, by any name and in any case: nothing changes.
  assert.equal(withTag('labels:Phish status:open', 'phish', SCHEMA), 'labels:Phish status:open')
  // A query the builder does not rewrite is kept, and the condition added to the whole.
  assert.equal(withTag('a or b', 'phish', SCHEMA), '(a or b) tag:phish')
  assert.equal(withTag('status:open', 'phish', TAKEN), 'status:open labels:phish')

  assert.equal(withoutTag('status:open tag:phish tag:vip', 'phish', SCHEMA), 'status:open tag:vip')
  assert.equal(withoutTag('tags:PHISH', 'phish', SCHEMA), '')
  assert.equal(withoutTag('status:open !tag:phish', 'phish', SCHEMA), 'status:open !tag:phish')
  assert.equal(withoutTag('a or tag:phish', 'phish', SCHEMA), 'a or tag:phish')

  assert.equal(toggleTag('status:open', 'phish', SCHEMA), 'status:open tag:phish')
  assert.equal(toggleTag('status:open tag:phish', 'phish', SCHEMA), 'status:open')
  assert.equal(toggleTag('tag:phish', 'vip', SCHEMA), 'tag:phish tag:vip')

  assert.equal(withoutTags('tag:phish status:open labels:vip !tag:test', SCHEMA), 'status:open !tag:test')
  assert.equal(withoutTags('status:open', SCHEMA), 'status:open')
})
