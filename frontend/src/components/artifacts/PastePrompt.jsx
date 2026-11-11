import { useEffect } from 'react'
import { Boxes, Crosshair, Link2, Search, X } from 'lucide-react'
import { Badge, Button } from '../ui/index.js'
import { PASTED_LABELS } from '../../domain/pasted.js'

/*
 * What Nik offers for text pasted (Ctrl+V outside a text field) or dragged
 * onto the app, when it recognises an address or an indicator (see
 * domain/pasted.js). Nothing happens until the analyst chooses: an address is
 * never opened by pasting it.
 */

/**
 * @param {{
 *   pasted: { kind: string, value: string, url: string | null, defanged: boolean, raw: string,
 *             known?: object | null } | null,
 *   busy?: boolean,
 *   error?: string | null,
 *   onScan: (url: string) => void,          // analyse the address with the isolated browser
 *   onSearch: (value: string) => void,      // open the search palette on it
 *   onLookup: (kind: string, value: string) => void,  // where seen + reputation
 *   onOpenKnown: (artifact: object) => void, // a hash that is an artifact already
 *   onDismiss: () => void,
 * }} props
 */
export default function PastePrompt({
  pasted,
  busy = false,
  error = null,
  onScan,
  onSearch,
  onLookup,
  onOpenKnown,
  onDismiss,
}) {
  useEffect(() => {
    if (!pasted) return undefined
    const onKey = (event) => event.key === 'Escape' && onDismiss()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [pasted, onDismiss])

  if (!pasted) return null
  const label = PASTED_LABELS[pasted.kind] ?? pasted.kind
  return (
    // A notice in a corner: the page behind stays usable, so it is not a dialog.
    <section
      role="region"
      aria-label="Pasted text"
      className="fixed bottom-4 right-4 z-[70] w-[min(28rem,calc(100vw-2rem))] border border-accent-strong bg-panel shadow-lg"
    >
      <div className="space-y-2 px-3.5 py-3">
        <div className="flex items-center gap-2">
          <p className="min-w-0 flex-1 font-mono text-[11px] tracking-wider text-fg-muted">RECOGNISED</p>
          <Badge color="cyan">{label}</Badge>
          <button
            type="button"
            aria-label="Dismiss"
            onClick={onDismiss}
            className="p-1 text-fg-muted hover:bg-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>
        <p className="break-all border border-line bg-canvas px-2.5 py-1.5 font-mono text-xs text-fg">{pasted.raw}</p>
        <p className="text-xs text-fg-muted">
          {pasted.defanged ? (
            <>
              Read as <span className="break-all font-mono text-fg">{pasted.value}</span>.{' '}
            </>
          ) : null}
          {pasted.url
            ? 'Nothing is opened until you choose.'
            : 'Search it in Nik, or see where it was seen and its reputation.'}
        </p>
        {pasted.known && (
          <p className="text-xs text-fg">
            Already analysed: <span className="font-mono">{pasted.known.name}</span>
          </p>
        )}
        {error && (
          <p role="alert" className="font-mono text-xs text-high">
            {error}
          </p>
        )}
      </div>
      <div className="flex flex-wrap gap-2 border-t border-line px-3.5 py-2.5">
        {pasted.known && (
          <Button size="sm" icon={Boxes} onClick={() => onOpenKnown(pasted.known)}>
            Open the analysis
          </Button>
        )}
        {pasted.url && (
          <Button
            size="sm"
            variant={pasted.known ? 'secondary' : 'primary'}
            icon={Link2}
            disabled={busy}
            onClick={() => onScan(pasted.url)}
          >
            {busy ? 'Starting…' : pasted.kind === 'url' ? 'Analyse URL' : 'Analyse as URL'}
          </Button>
        )}
        <Button size="sm" variant="secondary" icon={Search} onClick={() => onSearch(pasted.value)}>
          Search in Nik
        </Button>
        <Button size="sm" variant="secondary" icon={Crosshair} onClick={() => onLookup(pasted.kind, pasted.value)}>
          Where seen
        </Button>
      </div>
    </section>
  )
}
