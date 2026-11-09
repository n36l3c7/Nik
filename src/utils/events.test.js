import test from 'node:test'
import assert from 'node:assert/strict'
import { buildEvents, historyEventType } from './events.js'
import { topDomains, topSearchQueries, entryDomain } from './url.js'
import { createSocEngine } from './soc.js'

const engine = createSocEngine({ keywords: [] })

const history = [
  { id: 'a', url: 'https://www.google.com/search?q=mimikatz+download', visitTime: 3000 },
  { id: 'b', url: 'https://example.com/page', visitTime: 2000, isRedirect: true },
  { id: 'c', url: 'https://example.com/other', visitTime: 1000 },
  { id: 'd', url: 'not a url', visitTime: 500 },
]

test('buildEvents parses each URL once: domain and search query ride on the event', () => {
  const { historyEvents } = buildEvents({ history, engine })
  assert.deepEqual(
    historyEvents.map((e) => [e.eventType, e.domain, e.searchQuery]),
    [
      ['search', 'google.com', 'mimikatz download'],
      ['redirect', 'example.com', null],
      ['visit', 'example.com', null],
      ['visit', null, null],
    ],
  )
})

test('historyEventType accepts an already extracted query', () => {
  assert.equal(historyEventType({ url: 'https://x.test/' }, 'anything'), 'search')
  assert.equal(historyEventType({ url: 'https://x.test/', isRedirect: true }, null), 'redirect')
})

test('rankings reuse the parsed fields of events and parse raw entries', () => {
  const { historyEvents } = buildEvents({ history, engine })
  assert.deepEqual(topDomains(historyEvents, 1), [{ domain: 'example.com', count: 2 }])
  assert.deepEqual(topDomains(history, 1), [{ domain: 'example.com', count: 2 }])
  assert.deepEqual(topSearchQueries(historyEvents), [{ query: 'mimikatz download', count: 1 }])
  // A precomputed field wins over the URL, which is what makes the reuse real.
  assert.equal(entryDomain({ url: 'https://example.com/', domain: 'cached.test' }), 'cached.test')
  assert.equal(entryDomain({ url: 'https://example.com/', domain: null }), null)
  assert.equal(entryDomain({ url: 'https://example.com/' }), 'example.com')
})
