import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  charRange,
  copyTextOf,
  fieldRows,
  findSummary,
  hexDump,
  markedRows,
  matchLine,
  neighbours,
  numberedLines,
  pageStartFor,
  pageText,
  parseOffset,
  tokenizeXml,
  viewProblem,
  whereLine,
} from './sourceViewer.js'

test('an offset is hex with 0x or h, otherwise decimal', () => {
  assert.equal(parseOffset('0x1A00'), 6656)
  assert.equal(parseOffset('1a00h'), 6656)
  assert.equal(parseOffset('6656'), 6656)
  assert.equal(parseOffset(' 6_656 '), 6656)
  assert.equal(parseOffset('1a00'), null)
  assert.equal(parseOffset('-4'), null)
  assert.equal(parseOffset(''), null)
  assert.equal(parseOffset('0x'), null)
})

test('a page starts on a row of the dump and inside the file', () => {
  assert.equal(pageStartFor(100, 1000), 96)
  assert.equal(pageStartFor(5000, 1000), 992)
  assert.equal(pageStartFor(-3, 1000), 0)
  assert.equal(pageStartFor(7, 0), 0)
})

test('the pages before and after are null at the ends', () => {
  assert.deepEqual(neighbours(0, 200000), { previous: null, next: 65536 })
  assert.deepEqual(neighbours(65536, 200000), { previous: 0, next: 131072 })
  assert.deepEqual(neighbours(196608, 200000), { previous: 131072, next: null })
  assert.deepEqual(neighbours(100, 150, 65536), { previous: 0, next: null })
})

test('the page says which bytes it shows, and what it found past the end', () => {
  assert.equal(pageText(0, 65536, 68157440), '0x00000000–0x0000FFFF of 68,157,440 bytes')
  assert.equal(pageText(500, 0, 400), 'Nothing at 0x000001F4: the file has 400 bytes')
})

test('a dump has the offset, the bytes and the printable characters', () => {
  const hex = Buffer.from('Hello, world!\x00\x01\x02', 'latin1').toString('hex')
  const [line] = hexDump(hex, 0xd6a200).split('\n')
  assert.equal(line, '00D6A200  48 65 6c 6c 6f 2c 20 77  6f 72 6c 64 21 00 01 02  Hello, world!...')
  assert.equal(hexDump('4142', 16).split('\n').length, 1)
  assert.equal(hexDump(''.padEnd(34, '41'), 0).split('\n').length, 2)
  assert.equal(hexDump('', 0), '')
})

test('XML gets tokens that join back to the source', () => {
  const source =
    '<Event xmlns="urn:x"><System><EventID>4688</EventID></System><!-- c --><Data Name=\'A\'>a &amp; b</Data></Event>'
  const tokens = tokenizeXml(source)
  assert.equal(tokens.map((token) => token.text).join(''), source)
  assert.deepEqual(
    tokens.slice(0, 5).map((token) => [token.type, token.text]),
    [
      ['tag', '<Event'],
      ['plain', ' '],
      ['attr', 'xmlns'],
      ['plain', '='],
      ['value', '"urn:x"'],
    ],
  )
  assert.equal(tokens.find((token) => token.text === '4688').type, 'text')
  assert.equal(tokens.find((token) => token.text === '<!-- c -->').type, 'comment')
  assert.equal(tokens.find((token) => token.text === "'A'").type, 'value')
})

test('XML that is broken, or hostile, still comes back whole and as data', () => {
  for (const source of [
    '<a b="unclosed',
    '<',
    '<<>>',
    '<![CDATA[ <b> ',
    '<!-- never closed',
    'no tags at all',
    '<a\n  b = "1" / >',
  ]) {
    assert.equal(
      tokenizeXml(source)
        .map((token) => token.text)
        .join(''),
      source,
    )
  }
  // Markup in a value is a value: the tokens carry text, nothing here makes HTML.
  const [, , , , value] = tokenizeXml('<a b="<img src=x onerror=alert(1)>">')
  assert.equal(value.type, 'value')
  assert.deepEqual(tokenizeXml(''), [])
})

test('the lines of a text answer carry their numbers and the highlight', () => {
  assert.deepEqual(numberedLines('a\nb\nc', 10, [11, 11]), [
    { number: 10, text: 'a', on: false },
    { number: 11, text: 'b', on: true },
    { number: 12, text: 'c', on: false },
  ])
  assert.equal(numberedLines('x', 1, null)[0].on, false)
})

test('where a record is reads as a line', () => {
  assert.equal(
    whereLine({ offset: 0xd6a200, length: 1184, record: 27460, chunk: 215, extra: { a: 1 } }),
    'offset 0x00D6A200 · 1,184 bytes · record 27460 · chunk 215',
  )
  assert.equal(whereLine({ row: 3, line: 7 }), 'row 3 · line 7')
  assert.equal(whereLine(null), '')
})

test('the fields of a record come as name and text rows', () => {
  assert.deepEqual(fieldRows({ user: 'j', n: 3, empty: '', nothing: null, deep: { a: [1] } }), [
    ['user', 'j'],
    ['n', '3'],
    ['deep', '{"a":[1]}'],
  ])
  assert.deepEqual(
    fieldRows([
      ['time', '14:02'],
      ['x', ''],
    ]),
    [['time', '14:02']],
  )
  assert.deepEqual(fieldRows(undefined), [])
})

test('what could not be shown is said by its status, and what is copied by its kind', () => {
  assert.equal(viewProblem({ status: 404 }), 'This record has no original to show')
  assert.match(viewProblem({ status: 503 }), /not available/)
  assert.equal(viewProblem({ status: 502, message: 'cannot be reached' }), 'cannot be reached')
  assert.equal(
    copyTextOf({
      kind: 'fields',
      rows: [
        ['a', '1'],
        ['b', '2'],
      ],
    }),
    'a: 1\nb: 2',
  )
  assert.equal(copyTextOf({ kind: 'xml', text: '<a/>' }), '<a/>')
  assert.equal(copyTextOf(null), '')
})

test('a match is one line, and a search says what happened to it', () => {
  assert.equal(matchLine({ offset: 0x12a0, length: 24, encoding: 'utf-16le' }), '0x000012A0 · UTF-16 · 24 bytes')
  assert.equal(matchLine({ offset: 0, length: 1, encoding: 'hex' }), '0x00000000 · bytes · 1 byte')
  const found = { matches: [{ offset: 1, length: 3, encoding: 'utf-8' }], next: null, cut: false }
  assert.equal(findSummary(found).note, '1 match.')
  assert.equal(findSummary({ matches: [], next: null, cut: false }).note, 'Not found in this file.')
  // The limit of matches cuts the answer too: that is "more", not a time limit.
  const full = { matches: [{}, {}], next: 900, cut: true }
  assert.deepEqual([findSummary(full, 2).timedOut, findSummary(full, 2).more], [false, 900])
  const slow = { matches: [{}], next: 0x100000, cut: true }
  const timed = findSummary(slow, 2)
  assert.equal(timed.timedOut, true)
  assert.match(timed.note, /time limit, at 0x00100000/)
})

test('the bytes of a match are found again in the characters and the rows of the page', () => {
  assert.deepEqual(charRange('hello world', 100, 106, 5), { from: 6, to: 11 })
  // UTF-16 of "ab" is a, NUL, b, NUL: four characters for four bytes.
  assert.deepEqual(charRange('x\u0000a\u0000b\u0000', 0, 2, 4), { from: 2, to: 6 })
  // A two-byte character before the match moves it by one character, not two.
  assert.deepEqual(charRange('é-ok', 0, 3, 2), { from: 2, to: 4 })
  assert.equal(charRange('abc', 100, 0, 3), null)
  assert.deepEqual(markedRows(0, 20, 4), [1, 1])
  assert.deepEqual(markedRows(0, 30, 4), [1, 2])
  assert.deepEqual(markedRows(64, 70, 1), [0, 0])
})
