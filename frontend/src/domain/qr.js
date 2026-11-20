/*
 * A QR code, drawn here: the address an authenticator app reads when a second
 * factor is set up holds the secret, so it is never sent to a service that
 * draws codes, and no library is loaded for one picture.
 *
 * What is made: QR Code Model 2 (ISO/IEC 18004), the text as bytes (UTF-8),
 * error correction level M, versions 1 to 10 (up to 213 bytes, far more than
 * an otpauth:// address needs). `qrMatrix(text)` returns the rows of the
 * symbol, true for a dark module, without the quiet zone; null when the text
 * does not fit.
 */

// Level M, per version: error-correction codewords per block, then the blocks as [count, data codewords].
const BLOCKS = [
  null,
  [10, [[1, 16]]],
  [16, [[1, 28]]],
  [26, [[1, 44]]],
  [18, [[2, 32]]],
  [24, [[2, 43]]],
  [16, [[4, 27]]],
  [18, [[4, 31]]],
  [
    22,
    [
      [2, 38],
      [2, 39],
    ],
  ],
  [
    22,
    [
      [3, 36],
      [2, 37],
    ],
  ],
  [
    26,
    [
      [4, 43],
      [1, 44],
    ],
  ],
]
// Where the centres of the alignment patterns are, on both axes.
const ALIGNMENT = [
  null,
  [],
  [6, 18],
  [6, 22],
  [6, 26],
  [6, 30],
  [6, 34],
  [6, 22, 38],
  [6, 24, 42],
  [6, 26, 46],
  [6, 28, 50],
]
export const MAX_VERSION = BLOCKS.length - 1

const dataCodewords = (version) => BLOCKS[version][1].reduce((sum, [count, size]) => sum + count * size, 0)
// The byte count takes 8 bits up to version 9 and 16 from version 10.
const countBits = (version) => (version < 10 ? 8 : 16)

/** How many bytes of text a version holds. */
export function capacity(version) {
  return dataCodewords(version) - Math.ceil((4 + countBits(version)) / 8)
}

// ---------------------------------------------------------------------------
// Reed–Solomon over GF(256), the field of the standard (x^8 + x^4 + x^3 + x^2 + 1)
// ---------------------------------------------------------------------------
const EXP = new Uint8Array(512)
const LOG = new Uint8Array(256)
for (let i = 0, x = 1; i < 255; i++) {
  EXP[i] = x
  LOG[x] = i
  x <<= 1
  if (x & 0x100) x ^= 0x11d
}
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]

const multiply = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]])

/** The generator polynomial of `degree`, highest power first, without its leading 1. */
function generator(degree) {
  let poly = [1]
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0)
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j]
      next[j + 1] ^= multiply(poly[j], EXP[i])
    }
    poly = next
  }
  return poly.slice(1)
}

/** The error-correction codewords of one block of data. */
export function errorCorrection(data, degree) {
  const divisor = generator(degree)
  const rest = new Array(degree).fill(0)
  for (const byte of data) {
    const factor = byte ^ rest.shift()
    rest.push(0)
    for (let i = 0; i < degree; i++) rest[i] ^= multiply(divisor[i], factor)
  }
  return rest
}

// ---------------------------------------------------------------------------
// The codewords
// ---------------------------------------------------------------------------
function codewords(bytes, version) {
  const total = dataCodewords(version)
  const bits = []
  const push = (value, length) => {
    for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1)
  }
  push(0b0100, 4) // byte mode
  push(bytes.length, countBits(version))
  for (const byte of bytes) push(byte, 8)
  push(0, Math.min(4, total * 8 - bits.length)) // terminator
  while (bits.length % 8) bits.push(0)
  const data = []
  for (let i = 0; i < bits.length; i += 8) data.push(Number.parseInt(bits.slice(i, i + 8).join(''), 2))
  for (let pad = 0xec; data.length < total; pad ^= 0xec ^ 0x11) data.push(pad)

  // Cut into blocks, each with its error correction, then interleaved: the first codeword of each, the second…
  const [degree, groups] = BLOCKS[version]
  const blocks = []
  let offset = 0
  for (const [count, size] of groups) {
    for (let i = 0; i < count; i++) {
      const block = data.slice(offset, offset + size)
      offset += size
      blocks.push({ data: block, ec: errorCorrection(block, degree) })
    }
  }
  const out = []
  const longest = Math.max(...blocks.map((block) => block.data.length))
  for (let i = 0; i < longest; i++) for (const block of blocks) if (i < block.data.length) out.push(block.data[i])
  for (let i = 0; i < degree; i++) for (const block of blocks) out.push(block.ec[i])
  return out
}

// ---------------------------------------------------------------------------
// The symbol
// ---------------------------------------------------------------------------
/** The patterns every symbol of a version has; `reserved` marks the modules data must not use. */
function frame(version) {
  const size = 17 + 4 * version
  const modules = Array.from({ length: size }, () => new Array(size).fill(false))
  const reserved = Array.from({ length: size }, () => new Array(size).fill(false))
  const set = (row, col, dark) => {
    if (row < 0 || col < 0 || row >= size || col >= size) return
    modules[row][col] = dark
    reserved[row][col] = true
  }
  // Finder patterns with their separators.
  for (const [top, left] of [
    [0, 0],
    [0, size - 7],
    [size - 7, 0],
  ]) {
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        const ring = Math.max(Math.abs(r - 3), Math.abs(c - 3))
        set(top + r, left + c, ring !== 2 && ring <= 3)
      }
    }
  }
  // Alignment patterns, except where a finder pattern is.
  const centres = ALIGNMENT[version]
  for (const row of centres) {
    for (const col of centres) {
      if (reserved[row][col]) continue
      for (let r = -2; r <= 2; r++) {
        for (let c = -2; c <= 2; c++) set(row + r, col + c, Math.max(Math.abs(r), Math.abs(c)) !== 1)
      }
    }
  }
  // Timing patterns.
  for (let i = 8; i < size - 8; i++) {
    if (!reserved[6][i]) set(6, i, i % 2 === 0)
    if (!reserved[i][6]) set(i, 6, i % 2 === 0)
  }
  // The module that is always dark, and the room of the format information.
  set(size - 8, 8, true)
  for (let i = 0; i < 9; i++) {
    if (!reserved[8][i]) set(8, i, false)
    if (!reserved[i][8]) set(i, 8, false)
  }
  for (let i = 0; i < 8; i++) {
    if (!reserved[8][size - 1 - i]) set(8, size - 1 - i, false)
    if (!reserved[size - 1 - i][8]) set(size - 1 - i, 8, false)
  }
  // The version information, from version 7: 18 bits, twice.
  if (version >= 7) {
    let rest = version << 12
    for (let bit = 17; bit >= 12; bit--) if ((rest >>> bit) & 1) rest ^= 0x1f25 << (bit - 12)
    const info = (version << 12) | rest
    for (let i = 0; i < 18; i++) {
      const dark = ((info >>> i) & 1) === 1
      const a = Math.floor(i / 3)
      const b = size - 11 + (i % 3)
      set(a, b, dark)
      set(b, a, dark)
    }
  }
  return { size, modules, reserved }
}

const MASKS = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
]

/** The 15 bits of format information of level M and a mask. */
function formatBits(mask) {
  const data = (0b00 << 3) | mask // level M is 00
  let rest = data << 10
  for (let bit = 14; bit >= 10; bit--) if ((rest >>> bit) & 1) rest ^= 0x537 << (bit - 10)
  return ((data << 10) | rest) ^ 0x5412
}

function drawFormat(modules, size, mask) {
  const bits = formatBits(mask)
  const bit = (i) => ((bits >>> i) & 1) === 1
  // Around the top-left finder pattern…
  for (let i = 0; i <= 5; i++) modules[8][i] = bit(14 - i)
  modules[8][7] = bit(8)
  modules[8][8] = bit(7)
  modules[7][8] = bit(6)
  for (let i = 0; i <= 5; i++) modules[5 - i][8] = bit(5 - i)
  // …and split between the other two.
  for (let i = 0; i <= 6; i++) modules[size - 1 - i][8] = bit(14 - i)
  for (let i = 0; i <= 7; i++) modules[8][size - 8 + i] = bit(7 - i)
}

/** The score the standard gives a masked symbol: the lower, the easier to read. */
export function penalty(modules) {
  const size = modules.length
  let score = 0
  const line = (get) => {
    // Runs of five or more of one colour, and the finder-like pattern 1011101 with four light modules beside it.
    for (let a = 0; a < size; a++) {
      let run = 1
      for (let b = 1; b < size; b++) {
        if (get(a, b) === get(a, b - 1)) run++
        else {
          if (run >= 5) score += run - 2
          run = 1
        }
      }
      if (run >= 5) score += run - 2
      for (let b = 0; b + 10 < size; b++) {
        const at = (i) => get(a, b + i)
        const core = (o) => at(o) && !at(o + 1) && at(o + 2) && at(o + 3) && at(o + 4) && !at(o + 5) && at(o + 6)
        if (core(0) && !at(7) && !at(8) && !at(9) && !at(10)) score += 40
        if (!at(0) && !at(1) && !at(2) && !at(3) && core(4)) score += 40
      }
    }
  }
  line((a, b) => modules[a][b])
  line((a, b) => modules[b][a])
  // Blocks of two by two.
  let dark = 0
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (modules[r][c]) dark++
      if (r + 1 < size && c + 1 < size) {
        const colour = modules[r][c]
        if (modules[r][c + 1] === colour && modules[r + 1][c] === colour && modules[r + 1][c + 1] === colour) score += 3
      }
    }
  }
  // How far the share of dark modules is from a half, in steps of 5%.
  score += Math.floor(Math.abs((dark * 100) / (size * size) - 50) / 5) * 10
  return score
}

function build(words, version, mask) {
  const { size, modules, reserved } = frame(version)
  const grid = modules.map((row) => row.slice())
  // The bits go up and down in columns of two, from the bottom right, skipping the vertical timing pattern.
  let index = 0
  let up = true
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5
    for (let step = 0; step < size; step++) {
      const row = up ? size - 1 - step : step
      for (const col of [right, right - 1]) {
        if (reserved[row][col]) continue
        const byte = words[index >>> 3]
        const bit = byte === undefined ? 0 : (byte >>> (7 - (index & 7))) & 1 // the remainder bits are 0
        index++
        grid[row][col] = (bit === 1) !== MASKS[mask](row, col)
      }
    }
    up = !up
  }
  drawFormat(grid, size, mask)
  return grid
}

/**
 * The symbol for a text: rows of booleans (true: dark), without the quiet zone.
 * @param {string} text
 * @param {{ mask?: number }} [options]  `mask` forces one of the eight masks (the tests); the best is chosen otherwise
 * @returns {boolean[][] | null} null when the text is longer than version 10 holds
 */
export function qrMatrix(text, { mask = null } = {}) {
  const bytes = new TextEncoder().encode(String(text ?? ''))
  let version = 1
  while (version <= MAX_VERSION && capacity(version) < bytes.length) version++
  if (version > MAX_VERSION) return null
  const words = codewords(bytes, version)
  if (mask !== null) return build(words, version, mask)
  let best = null
  for (let candidate = 0; candidate < MASKS.length; candidate++) {
    const grid = build(words, version, candidate)
    const score = penalty(grid)
    if (best === null || score < best.score) best = { grid, score }
  }
  return best.grid
}

/** The symbol as the `d` of one SVG path, a square of side 1 per dark module, shifted by the quiet zone. */
export function qrPath(matrix, quiet = 4) {
  const parts = []
  matrix.forEach((row, r) => {
    let start = -1
    for (let c = 0; c <= row.length; c++) {
      if (row[c] && start < 0) start = c
      if (!row[c] && start >= 0) {
        parts.push(`M${start + quiet} ${r + quiet}h${c - start}v1h-${c - start}z`)
        start = -1
      }
    }
  })
  return parts.join('')
}
