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
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/50 p-4 backdrop-blur-sm"
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
          'flex max-h-[85vh] flex-col overflow-hidden rounded-xl border shadow-2xl',
          'border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900',
        ].join(' ')}
      >
        {/* Header: title + close button */}
        <header className="flex items-center justify-between gap-3 border-b border-slate-200 px-5 py-3.5 dark:border-slate-800">
          <h2 className="truncate text-sm font-semibold text-slate-800 dark:text-slate-100">
            {title}
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded-lg p-1 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 dark:hover:bg-slate-800 dark:hover:text-slate-300"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </header>

        {/* Scrollable body for long content */}
        <div className="overflow-y-auto p-5 text-sm text-slate-700 dark:text-slate-300">
          {children}
        </div>

        {/* Optional footer with the actions */}
        {footer && (
          <footer className="flex items-center justify-end gap-2 border-t border-slate-200 px-5 py-3.5 dark:border-slate-800">
            {footer}
          </footer>
        )}
      </div>
    </div>
  )
}
