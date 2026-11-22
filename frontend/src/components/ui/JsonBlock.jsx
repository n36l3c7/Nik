import { copied } from '../../domain/context.js'
import CopyButton from './CopyButton.jsx'

/**
 * A value shown as it is (a text as text, anything else as JSON), with the button that copies
 * it whole. The text can be selected with the mouse; the button copies all of it, also what
 * the box has scrolled out of sight.
 *
 * @param {{ value: any, what?: string, className?: string }} props
 *   what       the value in a few words, for the name of the button
 *              ("the result" → "Copy the result")
 *   className  the box (its height, its background)
 */
export default function JsonBlock({
  value,
  what = 'the value',
  className = 'max-h-80 bg-canvas text-[11px] leading-relaxed',
}) {
  const text = copied(value)
  return (
    <div className="relative">
      <pre className={`select-text overflow-auto p-2 pr-9 font-mono text-fg ${className}`}>{text}</pre>
      {/* The kit's button, in the corner of the box; it draws nothing for an empty text. */}
      {text && (
        <span className="absolute right-1 top-1 flex border border-line bg-panel p-0.5">
          <CopyButton text={text} label={`Copy ${what}`} />
        </span>
      )}
    </div>
  )
}
