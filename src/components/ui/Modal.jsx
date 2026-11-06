import { useEffect } from 'react'
import { X } from 'lucide-react'

/**
 * Modal — dialog window with a blurred backdrop.
 *
 * - Closes on the Escape key and on a backdrop click.
 * - Optional `footer` (typically Cancel/Confirm buttons).
 * - `maxWidth` is a Tailwind class (default 'max-w-lg').
 * - No portal: the fixed layer + z-50 is enough for this SPA.
 */
export default function Modal({
  open,
  onClose,
  title,
  children,
  footer = null,
  maxWidth = 'max-w-lg',
}) {
  // Close with the Escape key (listener active only when the modal is open)
  useEffect(() => {
    if (!open) return undefined
    const handleKeyDown = (event) => {
      if (event.key === 'Escape') onClose?.()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [open, onClose])

  if (!open) return null

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={typeof title === 'string' ? title : undefined}
      className="fixed inset-0 z-50 flex items-center justify-center bg-sunken/70 p-4 backdrop-blur-sm"
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
          'flex max-h-[85vh] flex-col overflow-hidden border border-line bg-panel shadow-2xl',
        ].join(' ')}
      >
        {/* Header: title + close button */}
        <header className="flex items-center justify-between gap-3 border-b border-line px-5 py-3">
          <h2 className="truncate font-mono text-sm font-semibold text-fg">
            {title}
          </h2>
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
        <div className="overflow-y-auto p-5 text-sm text-fg">
          {children}
        </div>

        {/* Optional footer with the actions */}
        {footer && (
          <footer className="flex items-center justify-end gap-2 border-t border-line px-5 py-3">
            {footer}
          </footer>
        )}
      </div>
    </div>
  )
}
