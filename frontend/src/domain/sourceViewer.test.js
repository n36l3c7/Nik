import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  copyTextOf,
  fieldRows,
  hexDump,
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
