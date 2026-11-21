import { Copy } from 'lucide-react'
import { useToast } from '../../context/ToastContext.jsx'
import { copied } from '../../domain/context.js'
import { copyText } from '../../lib/download.js'

/**
 * A value shown as it is (a text as text, anything else as JSON), with the button that copies
 * it whole. The text can be selected with the mouse; the button copies all of it, also what
 * the box has scrolled out of sight.
 *
 * @param {{ value: any, what?: string, className?: string }} props
 *   what       the value in a few words, for the name of the button and the confirmation
 *              ("the result" → "Copy the result")
 *   className  the box (its height, its background)
 */
export default function JsonBlock({
  value,
  what = 'the value',
  className = 'max-h-80 bg-canvas text-[11px] leading-relaxed',
}) {
  const { showToast } = useToast()
  const text = copied(value)
  const copy = async () => showToast({ message: (await copyText(text)) ? 'Copied.' : 'The browser refused to copy.' })
  return (
    <div className="group relative">
      <pre className={`select-text overflow-auto p-2 pr-9 font-mono text-fg ${className}`}>{text}</pre>
      <button
        type="button"
        aria-label={`Copy ${what}`}
        title={`Copy ${what}`}
        onClick={copy}
        className="absolute right-1 top-1 flex h-6 w-6 items-center justify-center border border-line bg-panel text-fg-muted opacity-70 hover:text-fg hover:opacity-100 focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent group-hover:opacity-100"
      >
        <Copy className="h-3.5 w-3.5" aria-hidden="true" />
      </button>
    </div>
  )
}
