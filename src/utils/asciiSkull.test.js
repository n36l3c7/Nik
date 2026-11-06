import assert from 'node:assert/strict'
import { test } from 'node:test'
import { SKULL_PRESETS, gazeFrame, microSkull, renderSkull, skullToText } from './asciiSkull.js'

const mirror = (line) =>
  [...line].reverse().map((ch) => ({ '/': '\\', '\\': '/' })[ch] ?? ch).join('')

test('renders exactly width × height cells for every preset', () => {
  for (const preset of Object.values(SKULL_PRESETS)) {
    const rows = renderSkull(preset)
    assert.equal(rows.length, preset.height)
    for (const row of rows) {
      assert.equal([...row.map((s) => s.text).join('')].length, preset.width)
    }
  }
})

test('is left-right symmetric in shape and eyes (shading is lit from the left)', () => {
  for (const eyes of ['open', 'closed', 'x']) {
    for (const size of [{ width: 40, height: 20 }, { width: 24, height: 12 }, { width: 60, height: 30 }]) {
      const rows = renderSkull({ ...size, eyes, crack: '+' })
      const shape = rows.map((row) => row.map((s) => s.text).join('').replace(/[^ ]/g, '#'))
      const eyeMask = rows.map((row) =>
        row.map((s) => (s.eye ? s.text : s.text.replace(/./g, ' '))).join(''),
      )
      for (const line of shape) assert.equal(line, mirror(line))
      for (const line of eyeMask) assert.equal(line, mirror(line), `${eyes} ${size.width}`)
    }
  }
})

test('marks eye cells so the UI can colour them', () => {
  const eyes = renderSkull({ width: 40, height: 20 }).flat().filter((s) => s.eye)
  assert.ok(eyes.length > 0)
  assert.ok(eyes.every((s) => /^@+$/.test(s.text)))
})

test('gaze moves the pupils sideways', () => {
  const pupilColumns = (gaze) =>
    skullToText(renderSkull({ width: 40, height: 20, gaze }))
      .split('\n')
      .flatMap((line) => [...line].flatMap((ch, i) => (ch === '@' ? [i] : [])))
  const centre = Math.min(...pupilColumns(0))
  assert.ok(Math.min(...pupilColumns(-1)) < centre)
  assert.ok(Math.min(...pupilColumns(1)) > centre)
})

test('closed and crossed-out eyes', () => {
  const closed = skullToText(renderSkull({ width: 40, height: 20, eyes: 'closed' }))
  const crossed = skullToText(renderSkull({ width: 40, height: 20, eyes: 'x' }))
  assert.ok(!closed.includes('@') && closed.includes('_'))
  assert.ok(!crossed.includes('@') && crossed.includes('X'))
})

test('animation cycles gaze and blinks; micro skull moods', () => {
  const frames = Array.from({ length: 16 }, (_, tick) => gazeFrame(tick))
  assert.deepEqual(new Set(frames.map((f) => f.gaze)), new Set([0, -1, 1]))
  assert.ok(frames.some((f) => f.eyes === 'closed'))
  assert.equal(microSkull(0), '(o.o)')
  assert.equal(microSkull(3, 'x'), '(x.x)')
  assert.equal(microSkull(3, 'closed'), '(-.-)')
})
