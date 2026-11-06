import { useEffect, useMemo, useState } from 'react'
import { SKULL_PRESETS, gazeFrame, microSkull, renderSkull } from '../../utils/asciiSkull.js'

/*
 * ============================================================================
 * ASCII SKULL — loading / error / empty illustrations
 * ============================================================================
 *
 *   <AsciiSkull preset="block" />                  animated: looks around, blinks
 *   <AsciiSkull preset="medium" eyes="x" tone="muted" />    error
 *   <AsciiSkull preset="medium" eyes="closed" tone="muted" /> empty / asleep
 *   <MicroSkull />  ·  <MicroSkull mood="x" />     inline "(o.o)" for buttons
 *
 * Presets (see utils/asciiSkull.js): block 64×32, large 60×30, medium 40×20,
 * small 24×12. Purely decorative: always aria-hidden, so pair it with a text
 * status. With "reduce motion" enabled in the OS the skull stays still.
 */

const TICK_MS = 400

const TONES = {
  accent: 'text-emerald-600 dark:text-emerald-400',
  muted: 'text-slate-400 dark:text-slate-500',
}

const EYE_TONES = {
  accent: 'text-red-500 dark:text-red-400',
  muted: 'text-red-500 dark:text-red-400',
}

// Block shading glyphs (░▒▓█) come from a fallback font in most monospace
// stacks; a tighter line height closes the gaps between their rows.
const FONT_SIZES = {
  block: 'text-[9px] leading-[0.82]',
  large: 'text-[10px] leading-none',
  medium: 'text-[11px] leading-none',
  small: 'text-[10px] leading-none',
}

/** True when the user asked the OS to reduce motion. */
function prefersReducedMotion() {
  return typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
}

/** A counter that advances every TICK_MS while `active` (and motion is allowed). */
export function useSkullTick(active = true) {
  const [tick, setTick] = useState(0)
  useEffect(() => {
    if (!active || prefersReducedMotion()) return undefined
    const timer = setInterval(() => setTick((t) => t + 1), TICK_MS)
    return () => clearInterval(timer)
  }, [active])
  return tick
}

/**
 * @param {{
 *   preset?: 'block' | 'large' | 'medium' | 'small',
 *   eyes?: 'animated' | 'open' | 'closed' | 'x',
 *   tone?: 'accent' | 'muted',
 *   className?: string,
 * }} props
 */
export default function AsciiSkull({ preset = 'medium', eyes = 'animated', tone = 'accent', className = '' }) {
  const animated = eyes === 'animated'
  const tick = useSkullTick(animated)
  const frame = animated ? gazeFrame(tick) : { eyes, gaze: 0 }
  const rows = useMemo(
    () => renderSkull({ ...(SKULL_PRESETS[preset] ?? SKULL_PRESETS.medium), ...frame }),
    [preset, frame.eyes, frame.gaze],
  )

  return (
    <div
      aria-hidden="true"
      className={[
        'select-none whitespace-pre font-mono',
        FONT_SIZES[preset] ?? FONT_SIZES.medium,
        TONES[tone] ?? TONES.accent,
        className,
      ].join(' ')}
    >
      {rows.map((segments, r) => (
        <div key={r}>
          {segments.map((segment, s) =>
            segment.eye ? (
              <span key={s} className={EYE_TONES[tone] ?? EYE_TONES.accent}>
                {segment.text}
              </span>
            ) : (
              <span key={s}>{segment.text}</span>
            ),
          )}
        </div>
      ))}
    </div>
  )
}

/**
 * Inline micro skull "(o.o)" — blinks while `mood` is 'animated'.
 * @param {{ mood?: 'animated' | 'closed' | 'x', className?: string }} props
 */
export function MicroSkull({ mood = 'animated', className = '' }) {
  const tick = useSkullTick(mood === 'animated')
  return (
    <span aria-hidden="true" className={`whitespace-pre font-mono ${className}`}>
      {microSkull(tick, mood === 'animated' ? 'open' : mood)}
    </span>
  )
}
