import { X } from 'lucide-react'

/**
 * Chip — a tag, or a thing something is linked to, as a small square box of
 * monospace text. The tags of an artifact and of an incident are drawn with
 * it, so a tag looks the same wherever it is put.
 *
 * With `onClick` its text is a button; with `onRemove` it ends with an × that
 * takes it away; `onMenu` is its right-click menu.
 *
 * @param {{
 *   children: import('react').ReactNode,
 *   onClick?: () => void,
 *   label?: string,          // the accessible name of the button, when the text does not say it
 *   title?: string,
 *   onRemove?: () => void,
 *   removeLabel?: string,
 *   onMenu?: (event: MouseEvent) => void,
 *   disabled?: boolean,      // its buttons do nothing for now (a change is being saved)
 * }} props
 */
export default function Chip({ children, onClick, label, title, onRemove, removeLabel, onMenu, disabled = false }) {
  return (
    <span
      onContextMenu={onMenu}
      title={onClick ? undefined : title}
      className="inline-flex items-center border border-line bg-canvas font-mono text-xs text-fg"
    >
      {onClick ? (
        <button
          type="button"
          aria-label={label}
          title={title}
          disabled={disabled}
          onClick={onClick}
          className="px-2 py-0.5 hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {children}
        </button>
      ) : (
        <span className="px-2 py-0.5">{children}</span>
      )}
      {onRemove && (
        <button
          type="button"
          aria-label={removeLabel}
          title={removeLabel}
          disabled={disabled}
          onClick={onRemove}
          className="border-l border-line px-1 py-0.5 text-fg-muted hover:bg-high-soft hover:text-high focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <X className="h-3 w-3" aria-hidden="true" />
        </button>
      )}
    </span>
  )
}
