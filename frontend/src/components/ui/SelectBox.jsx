import { useEffect, useRef } from 'react'

/**
 * The checkbox that selects a row of a list, or the rows of the page (in the
 * heading, where `state` 'some' draws it half ticked).
 *
 * The whole cell is the target, 32 pixels at least, and a click on it is not
 * a click on the row: the row still opens as it did. `onPick` is given the
 * event, for Shift.
 *
 * @param {{
 *   label: string,                         // "Select Case 12", "Select the rows on this page"
 *   checked?: boolean,
 *   state?: 'none' | 'some' | 'all',       // for the heading, instead of `checked`
 *   onPick: (event: MouseEvent) => void,
 *   disabled?: boolean,
 *   className?: string,
 * }} props
 */
export default function SelectBox({ label, checked = false, state = null, onPick, disabled = false, className = '' }) {
  const ref = useRef(null)
  const ticked = state ? state === 'all' : checked
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = state === 'some'
  }, [state])
  return (
    <label
      className={`flex h-8 min-w-8 cursor-pointer items-center justify-center ${className}`}
      // The row under the cell is not clicked, opened or given a menu by this.
      onClick={(event) => event.stopPropagation()}
      onDoubleClick={(event) => event.stopPropagation()}
    >
      <input
        ref={ref}
        type="checkbox"
        aria-label={label}
        aria-checked={state === 'some' ? 'mixed' : undefined}
        checked={ticked}
        disabled={disabled}
        // The click carries Shift; the box is drawn from the selection, not from itself.
        onClick={(event) => onPick(event)}
        onChange={() => {}}
        onKeyDown={(event) => event.stopPropagation()}
        className="h-4 w-4 cursor-pointer accent-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      />
    </label>
  )
}
