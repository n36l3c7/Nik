import { useRef } from 'react'
import { X } from 'lucide-react'
import { useLayer } from '../../lib/layers.js'

/**
 * Modal — dialog window with a blurred backdrop.
 *
 * - Closes on the Escape key (when it is the top dialog: Escape never closes
 *   the one under it) and on a backdrop click.
 * - Takes the focus when it opens, keeps Tab inside, and gives the focus
 *   back to what had it when it closes (lib/layers.js).
 * - Optional `footer` (typically Cancel/Confirm buttons).
 * - `maxWidth` is a Tailwind class (default 'max-w-lg').
 * - `tall` lets the dialog use nearly the whole height of the window (the
 *   isolated browser), instead of 85% of it.
 * - No portal: the fixed layer + z-50 is enough for this SPA.
 */
export default function Modal({ open, onClose, title, children, footer = null, maxWidth = 'max-w-lg', tall = false }) {
  const ref = useRef(null)
  useLayer(ref, { open, onClose })

  if (!open) return null

  return (
    <div
      ref={ref}
      role="dialog"
      aria-modal="true"
      tabIndex={-1}
      aria-label={typeof title === 'string' ? title : undefined}
      className={[
        'fixed inset-0 z-50 flex items-center justify-center bg-sunken/70 backdrop-blur-sm focus:outline-none',
        tall ? 'p-2' : 'p-4',
      ].join(' ')}
      // Close only if the mousedown happens directly on the backdrop
      // (avoids accidental closes when dragging from the content outward)
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose?.()
      }}
    >
      <div
        className={[
          'w-full',
          maxWidth,
          tall ? 'max-h-[96vh]' : 'max-h-[85vh]',
          'flex flex-col overflow-hidden border border-line bg-panel shadow-2xl',
        ].join(' ')}
      >
        {/* Header: title + close button */}
        <header className="flex items-center justify-between gap-3 border-b border-line px-5 py-3">
          <h2 className="truncate font-mono text-sm font-semibold text-fg">{title}</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="p-1 text-fg-muted transition-colors hover:bg-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </header>

        {/* Scrollable body for long content */}
        <div className="overflow-y-auto p-5 text-sm text-fg">{children}</div>

        {/* Optional footer with the actions */}
        {footer && (
          <footer className="flex items-center justify-end gap-2 border-t border-line px-5 py-3">{footer}</footer>
        )}
      </div>
    </div>
  )
}
