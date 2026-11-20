import { useIncidents } from '../../context/IncidentContext.jsx'
import { AsciiSkull, Button, TransferBar } from '../ui/index.js'

/**
 * ============================================================================
 * INCIDENT LOADING STATE — shown while an incident's full document downloads
 * ============================================================================
 * Non-blocking: it only fills the main area, so the sidebar, header and tab
 * bar stay usable (opening another incident cancels this download, and so
 * does Cancel). The block skull looks around while the bar shows the real
 * progress: a percentage when the server sends the size, otherwise the
 * megabytes received so far over an indeterminate bar.
 *
 * @param {{ name: string }} props  Display name of the incident being loaded.
 */
export default function IncidentLoadingState({ name }) {
  const { activeLoadProgress: progress, selectIncident } = useIncidents()
  const received = progress?.received ?? 0
  const total = progress?.total ?? null
  const pct = total ? Math.min(100, Math.round((received / total) * 100)) : null
  const mb = (bytes) => (bytes / 1048576).toFixed(1)

  return (
    <div aria-busy="true" className="flex min-h-full flex-wrap items-center justify-center gap-10 py-8">
      <AsciiSkull preset="block" className="max-w-full overflow-hidden" />
      <div className="flex w-full max-w-sm flex-col gap-3 font-mono">
        <p role="status" className="text-lg font-extrabold text-fg">
          Loading <span className="text-accent">{name}</span>…
        </p>
        <TransferBar label={`Downloading ${name}`} percent={pct} className="h-2.5" />
        <div className="flex justify-between text-xs text-fg-muted">
          <span>{pct !== null ? `${pct}%` : 'downloading'}</span>
          <span>{total ? `${mb(received)} / ${mb(total)} MB` : `${mb(received)} MB received`}</span>
        </div>
        <Button variant="secondary" size="sm" className="self-start" onClick={() => selectIncident(null)}>
          Cancel
        </Button>
      </div>
    </div>
  )
}
