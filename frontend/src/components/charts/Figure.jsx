import { ArrowDownRight, ArrowRight, ArrowUpRight, CircleCheck, TriangleAlert } from 'lucide-react'

/*
 * A widget that is a number: the figure, what it changed by against the
 * period before, and, for a gauge, how far it is from its target. The change
 * is said with a sign, an arrow and words, never by a colour alone: whether
 * more is good depends on what is counted, which a dashboard cannot know.
 */

const ARROWS = { up: ArrowUpRight, down: ArrowDownRight, same: ArrowRight }

/**
 * @param {{
 *   value: string,                                   // the figure, already written
 *   change?: { text: string, direction: 'up' | 'down' | 'same' } | null,
 *   against?: string | null,                         // "the 7 days before"
 *   onPick?: (() => void) | null,
 *   label: string,
 * }} props
 */
export function Stat({ value, change = null, against = null, onPick = null, label }) {
  const Arrow = change ? ARROWS[change.direction] : null
  const figure = (
    <span className="block truncate text-4xl font-semibold leading-none text-fg" title={value}>
      {value}
    </span>
  )
  return (
    <div className="flex h-full min-h-0 flex-col justify-center gap-2">
      {onPick ? (
        <button
          type="button"
          onClick={onPick}
          aria-label={`${label}: ${value}. Show them.`}
          className="min-w-0 text-left hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {figure}
        </button>
      ) : (
        figure
      )}
      {change && (
        <p className="flex items-center gap-1 text-xs text-fg-muted">
          <Arrow className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span className="font-medium text-fg">{change.text}</span>
          {against && <span className="truncate">against {against}</span>}
        </p>
      )}
    </div>
  )
}

/**
 * A figure against a target: a meter that fills to the target and says, in words and with an icon,
 * on which side of it the figure is.
 *
 * @param {{ value: number | null, target: number, text: string, targetText: string, lowerIsBetter?: boolean }} props
 */
export function Meter({ value, target, text, targetText, lowerIsBetter = false }) {
  const known = value != null
  const share = known ? Math.max(0, Math.min(1, Number(value) / target)) : 0
  const met = known && (lowerIsBetter ? Number(value) <= target : Number(value) >= target)
  const Icon = met ? CircleCheck : TriangleAlert
  return (
    <div className="flex h-full min-h-0 flex-col justify-center gap-2">
      <span className="block truncate text-4xl font-semibold leading-none text-fg">{text}</span>
      <div
        role="meter"
        aria-valuemin={0}
        aria-valuemax={target}
        aria-valuenow={known ? Number(value) : undefined}
        aria-valuetext={`${text} of a target of ${targetText}`}
        className="h-2 w-full overflow-hidden rounded-full bg-line-soft"
      >
        <div
          className={`h-full rounded-full ${met ? 'bg-accent' : 'bg-med-line'}`}
          style={{ width: `${share * 100}%` }}
        />
      </div>
      <p className="flex items-center gap-1 text-xs text-fg-muted">
        {known && <Icon className={`h-3.5 w-3.5 shrink-0 ${met ? 'text-accent' : 'text-med'}`} aria-hidden="true" />}
        <span>
          {known ? (met ? 'Within' : lowerIsBetter ? 'Above' : 'Below') : 'No figure against'} the target of{' '}
          <span className="font-medium text-fg">{targetText}</span>
        </span>
      </p>
    </div>
  )
}
