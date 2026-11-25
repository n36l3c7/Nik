import test from 'node:test'
import assert from 'node:assert/strict'
import {
  DEFAULT_THRESHOLDS,
  LIST_MAX,
  axisEnd,
  burstBar,
  burstBars,
  durationText,
  gapBands,
  markerItems,
  onGrid,
  readThresholds,
  summaryText,
} from './gapsBursts.js'
import { density } from './timeline.js'

const HOUR = 3_600_000

test('the thresholds come back as they were kept, and anything else is the default', () => {
  assert.deepEqual(readThresholds(JSON.stringify({ show: false, gap: 360, burst: 10 })), {
    show: false,
    gap: 360,
    burst: 10,
  })
  assert.deepEqual(readThresholds(null), DEFAULT_THRESHOLDS)
  assert.deepEqual(readThresholds('not json'), DEFAULT_THRESHOLDS)
  // A value that is not one of the choices is not kept.
  assert.deepEqual(readThresholds(JSON.stringify({ gap: 7, burst: 4, show: 'yes' })), DEFAULT_THRESHOLDS)
  assert.equal(DEFAULT_THRESHOLDS.gap, 120)
  assert.equal(DEFAULT_THRESHOLDS.burst, 5)
})

test('a duration is said in its two nearest units', () => {
  assert.equal(durationText(45), '45 min')
  assert.equal(durationText(60), '1 h')
  assert.equal(durationText(372), '6 h 12 min')
  assert.equal(durationText(1440), '1 d')
  assert.equal(durationText(1620), '1 d 3 h')
  assert.equal(durationText(0), '0 min')
  assert.equal(durationText(undefined), '0 min')
})

test('the line says how many gaps and bursts, and the longest gap', () => {
  const gaps = [{ minutes: 120 }, { minutes: 372 }, { minutes: 200 }]
  assert.equal(summaryText(gaps, [{}, {}]), '3 gaps, the longest 6 h 12 min · 2 bursts')
  assert.equal(summaryText([{ minutes: 60 }], []), '1 gap, the longest 1 h')
  assert.equal(summaryText([], [{}]), '1 burst')
  assert.equal(summaryText([], []), 'No gap, no burst')
})

test('the marks are items by time, each setting the range of its gap or of its slice', () => {
  const gaps = [{ from: 10 * HOUR, to: 16 * HOUR, minutes: 360 }]
  const bursts = [{ t: 2 * HOUR, count: 4812, factor: 31 }]
  const { items, more } = markerItems(gaps, bursts, HOUR)
  assert.deepEqual(
    items.map((item) => [item.kind, item.start, item.end]),
    [
      ['burst', 2 * HOUR, 3 * HOUR - 1],
      ['gap', 10 * HOUR, 16 * HOUR],
    ],
  )
  assert.equal(items[0].label, 'burst · 4,812 records, 31× the usual')
  assert.equal(items[1].label, 'gap · 6 h')
  assert.equal(more, 0)
  const many = Array.from({ length: LIST_MAX + 3 }, (_, i) => ({ from: i * HOUR, to: i * HOUR + 1, minutes: 30 }))
  assert.equal(markerItems(many, [], 0).items.length, LIST_MAX)
  assert.equal(markerItems(many, [], 0).more, 3)
})

const histogram = {
  from: 0,
  to: 10 * HOUR - 1,
  width: HOUR,
  // Slices 0, 1 and 8 hold records: the density holds only these.
  buckets: [
    { t: 0, count: 5 },
    { t: HOUR, count: 7 },
    { t: 8 * HOUR, count: 100 },
  ],
}

test('the bars are put on a grid of equal slices, the empty ones too', () => {
  const strip = onGrid(density(histogram, []))
  assert.equal(strip.bars.length, 9)
  assert.deepEqual(
    strip.bars.map((bar) => bar.host),
    [5, 7, 0, 0, 0, 0, 0, 0, 100],
  )
  assert.equal(strip.bars[3].t, 3 * HOUR)
  assert.equal(axisEnd(strip), 9 * HOUR)
  // Nothing dated: nothing to put on a grid.
  const empty = density(null, [])
  assert.equal(onGrid(empty), empty)
})

test('a gap is a band on the axis, cut to the axis, and a gap outside it is left out', () => {
  const strip = onGrid(density(histogram, []))
  const bands = gapBands(
    [
      { from: 2 * HOUR, to: 8 * HOUR, minutes: 360 },
      { from: 8 * HOUR + 30 * 60_000, to: 20 * HOUR, minutes: 690 },
      { from: 30 * HOUR, to: 40 * HOUR, minutes: 600 },
    ],
    strip,
  )
  assert.equal(bands.length, 2)
  assert.equal(bands[0].left.toFixed(2), ((2 / 9) * 100).toFixed(2))
  assert.equal(bands[0].width.toFixed(2), ((6 / 9) * 100).toFixed(2))
  // The second one runs past the end of the axis: it stops there.
  assert.equal((bands[1].left + bands[1].width).toFixed(2), '100.00')
  assert.deepEqual(gapBands([{ from: 0, to: 1, minutes: 1 }], onGrid(density(null, []))), [])
})

test('a burst marks the bar of its slice', () => {
  const strip = onGrid(density(histogram, []))
  assert.equal(burstBar({ t: 8 * HOUR }, strip), 8)
  assert.equal(burstBar({ t: 20 * HOUR }, strip), -1)
  assert.equal(burstBar({ t: -HOUR }, strip), -1)
  const marked = burstBars(
    [
      { t: 8 * HOUR, count: 100 },
      { t: 8 * HOUR + 1, count: 150 },
      { t: 99 * HOUR, count: 1 },
    ],
    strip,
  )
  assert.deepEqual([...marked.keys()], [8])
  assert.equal(marked.get(8).count, 150)
})
