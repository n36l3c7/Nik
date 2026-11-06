/*
 * ============================================================================
 * ASCII SKULL — pure generator behind the loading / error / empty states
 * ============================================================================
 *
 * Draws a symmetric skull in text characters on a `width` × `height` grid of
 * monospace cells, from simple shapes (cranium ellipse, cheeks, eye sockets,
 * nose, two rows of teeth, jaw). Bone is shaded with a character `ramp` (light
 * from the top-left); any size works, from 24 × 12 up to 64 × 32.
 *
 * `renderSkull()` returns rows of segments so the UI can colour the eyes:
 *   [ [ { text: '  .:-=', eye: false }, { text: '@@', eye: true }, … ], … ]
 *
 * Eyes: 'open' (pupils, shifted by `gaze` -1 … 1), 'closed' (a line),
 * 'x' (crossed out, for errors).
 */

/** Shading ramps, lightest first (index 0 is never used for bone). */
export const SKULL_RAMPS = {
  ascii: ' .:-=+*#%@',
  short: ' .:-=+*#',
  block: ' ░░▒▒▓▓██',
}

/** Ready-made sizes and looks used across the app (and kept for future use). */
export const SKULL_PRESETS = {
  block: { width: 64, height: 32, ramp: SKULL_RAMPS.block, tooth: '█', jaw: '▀', pupil: '█', crack: ' ', toothGap: ' ' },
  large: { width: 60, height: 30, ramp: SKULL_RAMPS.ascii },
  medium: { width: 40, height: 20, ramp: SKULL_RAMPS.ascii },
  small: { width: 24, height: 12, ramp: SKULL_RAMPS.short },
}

// Crack on the cranium, as (row, column) on the 60 × 30 reference grid.
const CRACK = [[3, 33], [4, 32], [5, 32], [6, 33], [7, 34], [8, 34], [9, 35]]

/**
 * @param {object} [options]
 * @param {number} [options.width=60]   columns
 * @param {number} [options.height=30]  rows
 * @param {string} [options.ramp]       shading characters, lightest first
 * @param {string} [options.tooth='#']  tooth character
 * @param {string} [options.toothGap='|'] character between teeth
 * @param {string} [options.jaw]        jaw character (default: ramp[3])
 * @param {string} [options.pupil='@']  pupil character
 * @param {string|null} [options.crack] crack character (null = '/' and '\')
 * @param {'open'|'closed'|'x'} [options.eyes='open']
 * @param {number} [options.gaze=0]     -1 (left) … 1 (right)
 * @returns {Array<Array<{text: string, eye: boolean}>>}
 */
export function renderSkull({
  width = 60,
  height = 30,
  ramp = SKULL_RAMPS.ascii,
  tooth = '#',
  toothGap = '|',
  jaw = null,
  pupil = '@',
  crack = null,
  eyes = 'open',
  gaze = 0,
} = {}) {
  const mid = (width - 1) / 2
  const eyeRow = Math.round((0.475 / 1.05) * height - 0.5)
  const eyeCols = [Math.round(mid - (0.37 * width) / 2), Math.round(mid + (0.37 * width) / 2)]
  const shift = Math.round((Math.max(-1, Math.min(1, gaze)) * width) / 20)
  const crackCells = new Set(
    height >= 24 ? CRACK.map(([r, c]) => `${Math.round((r * height) / 30)}:${Math.round((c * width) / 60)}`) : [],
  )

  const rows = []
  for (let r = 0; r < height; r++) {
    const y = ((r + 0.5) / height) * 1.05
    const segments = []
    const push = (text, eye) => {
      const last = segments[segments.length - 1]
      if (last && last.eye === eye) last.text += text
      else segments.push({ text, eye })
    }
    for (let c = 0; c < width; c++) {
      const x = ((c + 0.5) / width) * 2 - 1
      const cranium = (x / 0.92) ** 2 + ((y - 0.4) / 0.4) ** 2 <= 1 && y <= 0.66
      const cheek = y >= 0.6 && y <= 0.79 && Math.abs(x) <= 0.7 - (y - 0.6) * 1.25
      const upper = y > 0.79 && y <= 0.875 && Math.abs(x) <= 0.46
      const lower = y >= 0.905 && y <= 0.97 && Math.abs(x) <= 0.44
      const jawRow = y > 0.97 && y <= 1.03 && Math.abs(x) <= 0.44 - (y - 0.97) * 3
      if (!(cranium || cheek || upper || lower || jawRow)) {
        push(' ', false)
        continue
      }
      const inSocket = [-0.37, 0.37].some((ex) => ((x - ex) / 0.25) ** 2 + ((y - 0.47) / 0.12) ** 2 <= 1)
      if (inSocket) {
        push(...eyeCell(eyes, r - eyeRow, eyeCols.map((ec) => c - (ec + shift)), pupil))
      } else if (y >= 0.58 && y <= 0.72 && Math.abs(x) <= (0.72 - y) * 0.6) {
        push(' ', false) // nose
      } else if (crackCells.has(`${r}:${c}`)) {
        push(crack ?? (c % 2 ? '/' : '\\'), false)
      } else if (upper || lower) {
        push(Math.round(Math.abs(c - mid) + 0.5) % 4 === 0 ? toothGap : tooth, false)
      } else if (jawRow) {
        push(jaw ?? ramp[3], false)
      } else {
        const edge = y <= 0.66 ? 1 - ((x / 0.92) ** 2 + ((y - 0.4) / 0.4) ** 2) : 0.25
        const light = 0.55 + 0.45 * (-x * 0.3 - (y - 0.4) * 0.8)
        const v = Math.max(0, Math.min(0.999, 0.15 + edge * 1.1 * light))
        push(ramp[1 + Math.floor(v * (ramp.length - 1))], false)
      }
    }
    rows.push(segments)
  }
  return rows
}

/**
 * One cell inside an eye socket: [character, isEye]. `offsets` holds the
 * column offset from each eye's centre (left eye first); the right eye's
 * pattern is mirrored so both eyes are symmetric.
 */
function eyeCell(eyes, dr, offsets, pupil) {
  for (let i = 0; i < offsets.length; i++) {
    const mirrored = i === 1
    const dc = mirrored ? -offsets[i] : offsets[i]
    let ch = null
    if (eyes === 'closed') {
      if (dr === 0 && dc >= -2 && dc <= 1) ch = '_'
    } else if (eyes === 'x') {
      if (dr === 0 && (dc === -1 || dc === 0)) ch = 'X'
      else if (Math.abs(dr) === 1 && (dc === -2 || dc === 1)) ch = (dr === -1) === (dc === -2) ? '\\' : '/'
    } else if ((dr === 0 && dc >= -2 && dc <= 1) || (Math.abs(dr) === 1 && dc >= -1 && dc <= 0)) {
      ch = pupil
    }
    if (ch !== null) {
      if (mirrored && (ch === '/' || ch === '\\')) ch = ch === '/' ? '\\' : '/'
      return [ch, true]
    }
  }
  return [' ', false]
}

/** The skull as plain text (one line per row), e.g. for tests or logs. */
export function skullToText(rows) {
  return rows.map((segments) => segments.map((s) => s.text).join('')).join('\n')
}

/**
 * Animation frame for a tick counter: the skull looks left, centre, right,
 * centre, then blinks. Returns the `{ eyes, gaze }` options for renderSkull.
 */
export function gazeFrame(tick) {
  const sequence = [0, -1, -1, 0, 1, 1, 0, 'blink']
  const step = sequence[Math.floor(tick / 2) % sequence.length]
  return step === 'blink' ? { eyes: 'closed', gaze: 0 } : { eyes: 'open', gaze: step }
}

/** Micro skull for buttons, toasts and status lines: "(o.o)" and friends. */
export function microSkull(tick, mood = 'open') {
  if (mood === 'x') return '(x.x)'
  if (mood === 'closed') return '(-.-)'
  return ['(o.o)', '(o.o)', '(-.-)', '(o.o)', '(°.°)'][tick % 5]
}
