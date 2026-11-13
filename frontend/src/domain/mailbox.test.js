import test from 'node:test'
import assert from 'node:assert/strict'
import { dateRange, dayToMs, edgePath, layoutGraph, mailboxFormat, planLine, threadColour } from './mailbox.js'

const bytes = (text) => Uint8Array.from(text, (char) => char.charCodeAt(0))

test('a mailbox is told from another file by its first bytes, an archive by its name', () => {
  assert.equal(mailboxFormat({ name: 'inbox', head: bytes('From MAILER-DAEMON Thu') }), 'mbox')
  assert.equal(mailboxFormat({ name: 'archive.pst', head: bytes('!BDN\x00\x00') }), 'pst')
  assert.equal(mailboxFormat({ name: 'Maildir-backup.zip', head: bytes('PK\x03\x04') }), 'maildir')
  assert.equal(mailboxFormat({ name: 'mailbox.tar.gz', head: bytes('\x1f\x8b') }), 'maildir')
  // Any other archive is a file to analyse, an e-mail is an e-mail.
  assert.equal(mailboxFormat({ name: 'samples.zip', head: bytes('PK\x03\x04') }), null)
  assert.equal(mailboxFormat({ name: 'a.eml', head: bytes('From: someone@example.org') }), null)
  assert.equal(mailboxFormat({ name: 'a.txt', head: bytes('Fro') }), null)
})

test('a conversation runs down one lane and a second answer forks from its own', () => {
  // Newest first. 5 and 4 both answer 2; 3 is another conversation; 2 answers 1.
  const messages = [
    { seq: 5, parent: 2, thread: 1 },
    { seq: 4, parent: 2, thread: 1 },
    { seq: 3, parent: null, thread: 2 },
    { seq: 2, parent: 1, thread: 1 },
    { seq: 1, parent: null, thread: 1 },
  ]
  const { lanes, nodes, edges } = layoutGraph(messages)
  const lane = Object.fromEntries(nodes.map((node) => [node.seq, node.lane]))
  assert.deepEqual(lane, { 5: 0, 4: 1, 3: 2, 2: 0, 1: 0 })
  assert.equal(lanes, 3)
  assert.deepEqual(
    edges.map((edge) => [edge.from, edge.to, edge.fromLane, edge.toLane]),
    [
      [0, 3, 0, 0],
      [1, 3, 1, 0],
      [3, 4, 0, 0],
    ],
  )
  // A freed lane is used again; a parent that is not listed draws no edge.
  const later = layoutGraph([
    { seq: 9, parent: 8, thread: 1 },
    { seq: 8, parent: null, thread: 1 },
    { seq: 7, parent: 100, thread: 2 },
    { seq: 6, parent: null, thread: 3 },
  ])
  assert.deepEqual(
    later.nodes.map((node) => node.lane),
    [0, 0, 0, 0],
  )
  assert.equal(later.edges.length, 1)
  assert.deepEqual(layoutGraph([]), { lanes: 1, nodes: [], edges: [] })
})

test('an edge is a straight line in a lane and a bend across lanes', () => {
  const size = { rowHeight: 30, laneWidth: 16, inset: 10 }
  assert.equal(edgePath({ from: 0, to: 2, fromLane: 0, toLane: 0 }, size), 'M10,15 L10,75')
  assert.match(edgePath({ from: 1, to: 3, fromLane: 1, toLane: 0 }, size), /^M26,45 L26,86 C26,96 10,86 10,105$/)
  assert.equal(threadColour(1), threadColour(9))
  assert.notEqual(threadColour(1), threadColour(2))
})

test('dates and the plan of an import read plainly', () => {
  assert.equal(dateRange(Date.UTC(2026, 2, 3), Date.UTC(2026, 10, 12)), '3 Mar – 12 Nov 2026')
  assert.equal(dateRange(Date.UTC(2025, 11, 30), Date.UTC(2026, 0, 2)), '30 Dec 2025 – 2 Jan 2026')
  assert.equal(dateRange(null, 5), '')
  assert.equal(dayToMs('2026-11-01'), Date.UTC(2026, 10, 1))
  assert.equal(dayToMs('2026-11-01', true), Date.UTC(2026, 10, 1) + 86_399_999)
  assert.equal(dayToMs('soon'), null)
  assert.equal(
    planLine({ matches: 61, withConversations: 74, alreadyInNik: 2, tooLarge: 0, waiting: 0, max: 500 }),
    '61 messages match · 74 with their conversations · 2 already in Nik.',
  )
  assert.equal(
    planLine({ matches: 1, withConversations: 1, alreadyInNik: 0, tooLarge: 1, waiting: 40, max: 500 }),
    '1 message matches · 1 too large · 40 over the limit of 500, left for the next time.',
  )
})
