import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { copyText } from '../../lib/download.js'

/*
 * The small button that copies a text and shows a check for a moment.
 *
 * Nothing is drawn when there is no text. It copies through copyText
 * (lib/download.js), so it works on a server reached over plain HTTP too;
 * where the browser refuses all the same, the click does nothing.
 */

const BASE =
  'shrink-0 p-0.5 text-fg-muted hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const SHOWN_ON_HOVER = 'opacity-0 focus-visible:opacity-100 group-hover:opacity-100'

/**
 * @param {{
 *   text: string,
 *   label?: string,     // the accessible name: "Copy", "Copy command", "Copy sha256"
 *   title?: string,     // the tooltip, when it is not the label
 *   hover?: boolean,    // shown only while the surrounding `group` is hovered, or on focus
 *   small?: boolean,    // the 13 px icon of the lists of addresses
 * }} props
 */
export default function CopyButton({ text, label = 'Copy', title = label, hover = false, small = false }) {
  const [copied, setCopied] = useState(false)
  if (!text) return null

  const copy = async () => {
    if (!(await copyText(text))) return
    setCopied(true)
    setTimeout(() => setCopied(false), 1200)
  }

  const motion = !hover ? 'transition-colors' : small ? 'transition-opacity' : 'transition'
  const icon = small ? { size: 13 } : { className: 'h-3.5 w-3.5' }
  return (
    <button
      type="button"
      onClick={copy}
      aria-label={label}
      title={title}
      className={`${BASE} ${motion} ${hover ? SHOWN_ON_HOVER : ''}`.trim()}
    >
      {copied ? <Check {...icon} className={small ? 'text-accent' : 'h-3.5 w-3.5 text-accent'} /> : <Copy {...icon} />}
    </button>
  )
}
