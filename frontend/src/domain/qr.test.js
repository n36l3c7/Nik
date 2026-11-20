import test from 'node:test'
import assert from 'node:assert/strict'
import { MAX_VERSION, capacity, errorCorrection, penalty, qrMatrix, qrPath } from './qr.js'

/*
 * Known symbols: each was made by another implementation (the python-qrcode library: byte mode,
 * level M, the mask given) and is kept here as its rows, a hexadecimal number each (the leftmost
 * module is the highest bit). They cover a version without alignment pattern (1), with one (2, 6),
 * with several and the version information (8, 10), two blocks sizes in one symbol (8, 10), text
 * that is not ASCII, and five of the eight masks. While this file was written the encoder was also
 * compared with that library on 192 symbols (every version from 1 to 10, every mask), and what it
 * draws for an otpauth:// address was read back by a QR decoder (zxing).
 */
const KNOWN = [
  {
    text: 'Nik',
    mask: 2,
    version: 1,
    rows: [
      '1fc27f',
      '104541',
      '17575d',
      '17595d',
      '17515d',
      '105241',
      '1fd57f',
      '1c00',
      '17ce7c',
      'a13c1',
      '16ed6e',
      '1fafcd',
      'dd523',
      '1120',
      '1fca9a',
      '105037',
      '175a94',
      '175bc8',
      '175160',
      '104fc8',
      '1fd126',
    ],
  },
  {
    text: 'otpauth://totp/Nik%3Aanna?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Nik&digits=6&period=30',
    mask: 5,
    version: 6,
    rows: [
      '1fce9498e7f',
      '105da819d41',
      '1759fff645d',
      '1750414e85d',
      '17436dc7d5d',
      '10411950941',
      '1fd5555557f',
      '127742100',
      '1058e81bcce',
      '1f9bc636ffa',
      '577708ec2c',
      '1094f37167a',
      '19e0d89a8c2',
      '1b8ba082f78',
      'b45a1fb938',
      'd94f5200fe',
      '144af8ec124',
      '83646a7dfd',
      '3eebe2ff59',
      '7b3628311b',
      '196356c28a2',
      '69db04cc9c',
      'cc1150e9f0',
      '1199b0773ab',
      'a71c7b82f0',
      '18257ba32f9',
      '5548d4f000',
      '2eb51253e',
      '1df030e520c',
      '1a951d96ff0',
      '1fdedd27761',
      '101fc315418',
      '12794a5e1fc',
      '116e6bb16',
      '1fc1698f954',
      '104e3c4831b',
      '174f08eb3f4',
      '17465579782',
      '1740848f0fc',
      '1043df16595',
      '1fdb7e7ea1c',
    ],
  },
  {
    text: 'ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    mask: 0,
    version: 8,
    rows: [
      '1fcfd8d88817f',
      '105aa8c999f41',
      '174667dccc35d',
      '174d4e988825d',
      '17514e7ddd85d',
      '104e2b44ccc41',
      '1fd555555557f',
      'c414733000',
      '154a847f77512',
      '1686683222123',
      '1af7956333037',
      '1ab41c3333132',
      'ce8533777473',
      '1625caa222023',
      '5e94ff333137',
      'd0856b088832',
      '1a4344f5ddc73',
      '73fe02088823',
      '4e47171ddd37',
      '151bc43b33032',
      'f7d043f77473',
      '807e42a22023',
      'dfc917f331f7',
      '511c8c733312',
      'f53405777753',
      '31b144622313',
      '9fc75ff331f7',
      '1f1fb883332c2',
      '5dae93f775c3',
      '1b0a1daa22383',
      '1ef3c8bf331d7',
      'e1a412e665c1',
      '174eb48e221c0',
      '1db7ec0b77783',
      '94d511e665d7',
      '3a4808f331c2',
      '18f5380f775c3',
      '41b948a22383',
      '8d42d9f331d7',
      'e17a48f331c2',
      '1c7dc4ff775f3',
      '1cb4c622313',
      '1fcd455733157',
      '104c38c733112',
      '175583ff775f3',
      '1742c2f622331',
      '175167f333377',
      '1041d6a488a22',
      '1fdbc4f5ddf33',
    ],
  },
  {
    text: 'ggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg',
    mask: 7,
    version: 10,
    rows: [
      '1fc71c3eeeeee7f',
      '10424a55e85e241',
      '1745cb985e8565d',
      '174cb634444425d',
      '17418f7fca7ca5d',
      '1056d7345e85c41',
      '1fd55555555557f',
      'c6b0c57a1400',
      '12d320e7e9f2aa0',
      '1f8b2ac11111013',
      '8efa3a217a16a9',
      '1028a067a17a278',
      'e713943bbbb8b3',
      '5af28c83583481',
      '6d5488fa17a072',
      '14b239c33333030',
      '3d569ca9f29c21',
      '81db225835825a',
      '4432feb333323b',
      '1a268c4a17a14a3',
      'e5cb46729f2afa',
      'cb8f1411111013',
      '1dfbbfa217a16a9',
      '17a05127a17a278',
      '12d7fb43bbbb8b3',
      '15bf67083583481',
      '1ff6dcfe17a1f2',
      '1b1092047333111',
      'f50e90d5f29f51',
      '118dc64435811a',
      '1fcf4eff3331fb',
      '6055081d7a1553',
      '65662ac69f2a8a',
      '1b0a354c5111140',
      '84cb6e3d7a1578',
      'f9fcbac617a38b',
      '5ccbb08fbbb8c1',
      '1426d5c575835d1',
      '2fa6e8e617a3a2',
      'c01ac88f3331c1',
      'd682601df29c51',
      '181c0668c35830a',
      'f612daaf3331eb',
      'da23dc1d7a1553',
      '864f36c69f2a8a',
      '1c1e4a4c5111143',
      '14e6f3e3d7a1579',
      '1f37afac617a388',
      '64964ffbbb9f3',
      '18e40c7583511',
      '1fc198cd617a152',
      '1054664c7333111',
      '17409447df29df1',
      '175ebfab835817b',
      '174bc16fb3333b9',
      '104c940c17a1580',
      '1fdaadeba9f297a',
    ],
  },
  {
    text: 'è€ unicode ✓',
    mask: 4,
    version: 2,
    rows: [
      '1fdb47f',
      '1047141',
      '174b95d',
      '175165d',
      '1758c5d',
      '1058e41',
      '1fd557f',
      '13600',
      '1175ff9',
      '1b0a010',
      '253da9',
      '68395a',
      'd718e0',
      '1d98f10',
      '5c15b',
      '20d779',
      '1ae6df5',
      '1111d',
      '1fd3d5d',
      '1046b1c',
      '17519f5',
      '1748ee3',
      '17401ee',
      '1041626',
      '1fdee5f',
    ],
  },
]

const rowsOf = (matrix) => matrix.map((row) => BigInt('0b' + row.map((cell) => (cell ? 1 : 0)).join('')).toString(16))

test('the symbol is the one another implementation makes, module for module', () => {
  for (const { text, mask, version, rows } of KNOWN) {
    const matrix = qrMatrix(text, { mask })
    assert.equal(matrix.length, 17 + 4 * version, text)
    assert.ok(
      matrix.every((row) => row.length === matrix.length),
      'square',
    )
    assert.deepEqual(rowsOf(matrix), rows, `${text.slice(0, 20)} (mask ${mask})`)
  }
})

test('the error correction of the standard: its worked example', () => {
  // ISO/IEC 18004, annex I ("01234567", version 1-M): the data codewords and their ten error-correction codewords.
  const data = [0x10, 0x20, 0x0c, 0x56, 0x61, 0x80, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11]
  assert.deepEqual(errorCorrection(data, 10), [0xa5, 0x24, 0xd4, 0xc1, 0xed, 0x36, 0xc7, 0x87, 0x2c, 0x55])
})

test('the smallest version that holds the text is used, and too long a text gives nothing', () => {
  assert.deepEqual(
    Array.from({ length: MAX_VERSION }, (_, i) => capacity(i + 1)),
    [14, 26, 42, 62, 84, 106, 122, 152, 180, 213],
  )
  assert.equal(qrMatrix('').length, 21)
  assert.equal(qrMatrix('x'.repeat(14)).length, 21)
  assert.equal(qrMatrix('x'.repeat(15)).length, 25)
  // Bytes are counted, not characters.
  assert.equal(qrMatrix('é'.repeat(7)).length, 21)
  assert.equal(qrMatrix('é'.repeat(8)).length, 25)
  assert.equal(qrMatrix('x'.repeat(213)).length, 57)
  assert.equal(qrMatrix('x'.repeat(214)), null)
})

test('left to itself it takes the mask with the lowest penalty', () => {
  const text = 'otpauth://totp/Nik%3Aanna?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Nik&digits=6&period=30'
  const scores = Array.from({ length: 8 }, (_, mask) => penalty(qrMatrix(text, { mask })))
  assert.equal(penalty(qrMatrix(text)), Math.min(...scores))
  assert.ok(new Set(scores).size > 1, 'the masks do differ')
})

test('the penalty counts runs, blocks, finder-like patterns and the balance', () => {
  const blank = (size, dark) => Array.from({ length: size }, () => new Array(size).fill(dark))
  // All one colour, 12 by 12: every row and column is a run of 12 (10 each), every 2x2 block counts 3,
  // and the balance is as far from a half as it gets (100).
  assert.equal(penalty(blank(12, false)), 24 * 10 + 121 * 3 + 100)
  assert.equal(penalty(blank(12, true)), 24 * 10 + 121 * 3 + 100)
  // A checkerboard has none of it.
  const checks = blank(12, false).map((row, r) => row.map((_, c) => (r + c) % 2 === 0))
  assert.equal(penalty(checks), 0)
  // One row made 1011101 followed by four light modules, on that checkerboard: the pattern (40) and its runs.
  const pattern = checks.map((row) => row.slice())
  pattern[0] = [true, false, true, true, true, false, true, false, false, false, false, true]
  assert.ok(penalty(pattern) >= 40)
})

test('the path draws each run of dark modules once, inside the quiet zone', () => {
  const path = qrPath([
    [true, true, false],
    [false, false, true],
  ])
  assert.equal(path, 'M4 4h2v1h-2zM6 5h1v1h-1z')
  assert.equal(qrPath([[true]], 0), 'M0 0h1v1h-1z')
})
