/*
 * Gaps and bursts on the density of the Timeline (components/tabs/timeline/GapsBursts.jsx): the choices of the
 * two thresholds, how they are kept, and how the server's `gaps` and `bursts` (`GET .../histogram`) become marks
 * on the bars. A gap is a stretch with no record for at least the threshold; a burst is a slice of the histogram
 * with at least `factor` times the usual (the median of the slices that hold any).
 */

/** The choices of the gap threshold, in minutes (the API's `gapMinutes`). */
export const GAP_OPTIONS = [
  { value: 30, label: '30 min' },
  { value: 60, label: '1 h' },
  { value: 120, label: '2 h' },
  { value: 360, label: '6 h' },
  { value: 1440, label: '24 h' },
]

/** The choices of the burst threshold, as a factor of the usual (the API's `burstFactor`). */
export const BURST_OPTIONS = [
  { value: 3, label: '3×' },
  { value: 5, label: '5×' },
  { value: 10, label: '10×' },
]

export const DEFAULT_THRESHOLDS = { show: true, gap: 120, burst: 5 }
export const STORAGE_KEY = 'nik.timeline.gaps'
// The most items the line lists: the rest are said, not drawn.
export const LIST_MAX = 12

const number = (n) => n.toLocaleString('en-US')

/** The thresholds kept in this browser, read defensively: what is not one of the choices is the default. */
export function readThresholds(raw) {
  let parsed
  try {
    parsed = JSON.parse(raw)
  } catch {
    // Nothing stored, or something else wrote there: the defaults.
  }
  const gap = GAP_OPTIONS.some((item) => item.value === parsed?.gap) ? parsed.gap : DEFAULT_THRESHOLDS.gap
  const burst = BURST_OPTIONS.some((item) => item.value === parsed?.burst) ? parsed.burst : DEFAULT_THRESHOLDS.burst
  const show = typeof parsed?.show === 'boolean' ? parsed.show : DEFAULT_THRESHOLDS.show
  return { show, gap, burst }
}

/** A duration in minutes in words: "45 min", "6 h 12 min", "2 d 3 h". */
export function durationText(minutes) {
  const total = Math.max(0, Math.round(Number(minutes) || 0))
  if (total < 60) return `${number(total)} min`
  const hours = Math.floor(total / 60)
  if (hours < 24) return total % 60 ? `${hours} h ${total % 60} min` : `${hours} h`
  const days = Math.floor(hours / 24)
  return hours % 24 ? `${days} d ${hours % 24} h` : `${days} d`
}

/** "3 gaps, the longest 6 h 12 min · 2 bursts"; "No gap, no burst" for none. */
export function summaryText(gaps = [], bursts = []) {
  const parts = []
  if (gaps.length > 0) {
    const longest = Math.max(...gaps.map((gap) => gap.minutes))
    parts.push(`${number(gaps.length)} ${gaps.length === 1 ? 'gap' : 'gaps'}, the longest ${durationText(longest)}`)
  }
  if (bursts.length > 0) parts.push(`${number(bursts.length)} ${bursts.length === 1 ? 'burst' : 'bursts'}`)
  return parts.length > 0 ? parts.join(' · ') : 'No gap, no burst'
}

/**
 * The marks as items of a list, by time: `{ kind, key, label, start, end }`, the range each sets. `width` is the
 * width of a slice of the histogram in ms (a burst is one slice). At most `LIST_MAX`; `more` counts the rest.
 */
export function markerItems(gaps = [], bursts = [], width = 0) {
  const items = [
    ...gaps.map((gap) => ({
      kind: 'gap',
      key: `gap:${gap.from}`,
      label: `gap · ${durationText(gap.minutes)}`,
      start: gap.from,
      end: gap.to,
    })),
    ...bursts.map((burst) => ({
      kind: 'burst',
      key: `burst:${burst.t}`,
      label: `burst · ${number(burst.count)} records, ${burst.factor}× the usual`,
      start: burst.t,
      end: burst.t + Math.max(0, width - 1),
    })),
  ].sort((a, b) => a.start - b.start || (a.kind < b.kind ? -1 : 1))
  return { items: items.slice(0, LIST_MAX), more: Math.max(0, items.length - LIST_MAX) }
}

/**
 * The bars of the density on a grid of equal slices of time, the empty ones too (the density holds only the
 * slices that have something): the bars are then in their place on the axis, so a gap can be drawn across them.
 * `{ from, width, bars, peak }` as `density()` gives, `bars` with one entry for each slice from the first to the last.
 */
export function onGrid(strip) {
  if (!strip || strip.bars.length === 0 || !(strip.width > 0)) return strip
  const held = new Map(strip.bars.map((bar) => [Math.round((bar.t - strip.from) / strip.width), bar]))
  const last = Math.max(...held.keys())
  const bars = []
  for (let index = 0; index <= last; index += 1) {
    bars.push(held.get(index) ?? { t: strip.from + index * strip.width, host: 0, docs: 0 })
  }
  return { ...strip, bars }
}

/** The end of the axis of a strip on a grid. */
export const axisEnd = (strip) => strip.from + strip.bars.length * strip.width

/**
 * The gaps as bands on the axis of the strip: `{ key, left, width, minutes }` in per cent of the axis, the part
 * of the gap inside the axis only. A gap outside it is left out.
 */
export function gapBands(gaps = [], strip) {
  if (!strip || strip.bars.length === 0) return []
  const start = strip.from
  const span = axisEnd(strip) - start
  const bands = []
  for (const gap of gaps) {
    const from = Math.max(gap.from, start)
    const to = Math.min(gap.to, start + span)
    if (to <= from) continue
    bands.push({
      key: `gap:${gap.from}`,
      left: ((from - start) / span) * 100,
      width: ((to - from) / span) * 100,
      minutes: gap.minutes,
      from: gap.from,
      to: gap.to,
    })
  }
  return bands
}

/** The index of the bar of a strip a burst falls in (-1 when it is outside), by the start of its slice. */
export function burstBar(burst, strip) {
  if (!strip || !(strip.width > 0)) return -1
  const index = Math.floor((burst.t - strip.from) / strip.width)
  return index >= 0 && index < strip.bars.length ? index : -1
}

/** The indexes of the bars that are bursts, with the burst of each: `Map<index, burst>` (the largest when two share one). */
export function burstBars(bursts = [], strip) {
  const marked = new Map()
  for (const burst of bursts) {
    const index = burstBar(burst, strip)
    if (index < 0) continue
    const held = marked.get(index)
    if (!held || burst.count > held.count) marked.set(index, burst)
  }
  return marked
}
