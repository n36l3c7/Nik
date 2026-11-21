import { useSyncExternalStore } from 'react'
import { amountText, percentOf } from '../../domain/transfers.js'
import { dismissTransfer, retryTransfer, subscribeTransfers, transfersNow } from '../../lib/transfers.js'
import { MicroSkull } from './AsciiSkull.jsx'

/*
 * ============================================================================
 * WAIT — how Nik shows that something is on its way
 * ============================================================================
 *
 * One look for every upload, download and wait on the server
 * (domain/transfers.js has the rule):
 *
 *   <Wait>Preparing the export…</Wait>          the (o.o) wait and a sentence,
 *                                               when the size is not known
 *   <TransferBar label="Uploading a.bin"        a bar with how much is done,
 *                progress={{ sent, total }} />  when it is
 *   <Button waiting={busy}>Export</Button>      the (o.o) in the button that
 *                                               started a short wait
 *   <Transfers />                               the tray (mounted once, by App)
 *                                               for what has no place of its
 *                                               own on the screen: lib/transfers.js
 *
 * Whole pages and panels that load keep the large skull that looks around
 * (AsciiSkull, IncidentLoadingState); the bar there is this one.
 */

/**
 * The (o.o) wait with its sentence.
 * @param {{ children: React.ReactNode, className?: string, inline?: boolean }} props
 *   `inline` draws it as a span, inside a line of text or a table cell.
 */
export function Wait({ children, className = '', inline = false }) {
  const Tag = inline ? 'span' : 'p'
  return (
    <Tag
      role="status"
      className={`${inline ? 'inline-flex' : 'flex'} items-center gap-2 font-mono text-sm text-fg-muted ${className}`}
    >
      <MicroSkull className="shrink-0 text-accent" />
      <span className="min-w-0">{children}</span>
    </Tag>
  )
}

/**
 * A bar for a transfer: as full as what is done when the size is known, a
 * part of it that pulses when it is not.
 * @param {{
 *   label: string,                                  // its accessible name: "Uploading a.bin"
 *   progress?: { sent?: number, received?: number, total?: number | null } | null,
 *   percent?: number | null,                        // given instead of `progress` when someone else counts
 *   className?: string,
 * }} props
 */
export function TransferBar({ label, progress = null, percent = undefined, className = '' }) {
  const pct = percent === undefined ? percentOf(progress) : percent
  return (
    <div
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={pct ?? undefined}
      className={`relative h-1.5 w-full overflow-hidden border border-line bg-panel ${className}`}
    >
      {pct !== null ? (
        <div className="h-full bg-accent transition-[width]" style={{ width: `${pct}%` }} />
      ) : (
        <div className="absolute inset-y-0 w-1/3 animate-pulse bg-accent/70" />
      )}
    </div>
  )
}

/**
 * A transfer with everything it says: the (o.o), the sentence, the bar and
 * the amounts when the size is known; the (o.o) and the sentence when not.
 * @param {{ label: string, progress?: object | null, className?: string }} props
 */
export function Transfer({ label, progress = null, className = '' }) {
  const pct = percentOf(progress)
  if (pct === null) {
    const passed = amountText(progress)
    return (
      <Wait className={className}>
        {label}…{passed ? ` ${passed}` : ''}
      </Wait>
    )
  }
  return (
    <div className={`flex flex-col gap-1 font-mono ${className}`}>
      <Wait className="text-xs">
        {label} · {pct}%
      </Wait>
      <TransferBar label={label} progress={progress} />
      <span className="text-[11px] text-fg-subtle">{amountText(progress)}</span>
    </div>
  )
}

/** The tray of the transfers that have no place of their own on the screen. Mounted once, by App. */
export function Transfers() {
  const list = useSyncExternalStore(subscribeTransfers, transfersNow, transfersNow)
  if (list.length === 0) return null
  return (
    <ul
      aria-label="Transfers"
      className="fixed bottom-4 left-[4.5rem] z-[60] flex w-80 max-w-[calc(100vw-5.5rem)] flex-col gap-2"
    >
      {list.map((item) => (
        <li key={item.id} className="border border-line bg-raised px-3 py-2 shadow-lg">
          {item.failed ? (
            // Cut by a restart of the server: said, and sent again from here (lib/transfers.js).
            <div className="flex flex-col gap-2 font-mono">
              <p role="alert" className="text-xs text-high-fg">
                {item.failed}
              </p>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => retryTransfer(item.id)}
                  className="border border-line bg-canvas px-2 py-0.5 text-xs text-fg hover:bg-panel focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  Try again
                </button>
                <button
                  type="button"
                  onClick={() => dismissTransfer(item.id)}
                  className="px-2 py-0.5 text-xs text-fg-muted hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  Dismiss
                </button>
              </div>
            </div>
          ) : (
            <Transfer label={item.label} progress={item} />
          )}
        </li>
      ))}
    </ul>
  )
}
