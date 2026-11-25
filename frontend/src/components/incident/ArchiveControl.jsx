import { useState } from 'react'
import { Archive, ArchiveRestore } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { ARCHIVE_EFFECT, UNARCHIVE_EFFECT, canArchive, isArchived } from '../../domain/archive.js'
import { formatDateTime } from '../../lib/time.js'
import { noteEvidenceChanged } from '../../lib/useEvidenceSummary.js'
import { Button, Modal } from '../ui/index.js'

/*
 * Archiving an incident (7.0), from its header: "Archive" on a closed incident, "Take out of the archive" on
 * an archived one, each after a question that says what it does. It asks for `incidents.archive`; the server
 * answers with a sentence when it cannot (the incident is not closed, a file of it is being read).
 */

/**
 * The button of the header and its question.
 * @param {{ incident: object, className?: string }} props
 */
export function ArchiveControl({ incident, className = '' }) {
  const { can } = useAuth()
  const { setArchived } = useIncidents()
  const [asking, setAsking] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const archived = isArchived(incident)
  if (!incident || !can('incidents.archive') || !(archived || canArchive(incident))) return null

  const close = () => {
    if (busy) return
    setAsking(false)
    setError('')
  }
  const confirm = async () => {
    setBusy(true)
    setError('')
    try {
      await setArchived(incident.id, !archived)
      noteEvidenceChanged(incident.id)
      setAsking(false)
    } catch (failure) {
      setError(failure?.message || 'The server refused.')
    } finally {
      setBusy(false)
    }
  }
  const Icon = archived ? ArchiveRestore : Archive
  const label = archived ? 'Take out of the archive' : 'Archive'

  return (
    <>
      <button
        type="button"
        onClick={() => setAsking(true)}
        aria-label={label}
        title={archived ? 'Take this incident out of the archive' : 'Archive this closed incident'}
        className={`flex h-9 w-9 shrink-0 items-center justify-center border border-line text-fg-muted transition-colors hover:bg-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${className}`}
      >
        <Icon className="h-4 w-4" aria-hidden="true" />
      </button>
      <Modal
        open={asking}
        onClose={close}
        title={archived ? 'Take the incident out of the archive' : 'Archive the incident'}
        footer={
          <>
            <Button variant="secondary" onClick={close} disabled={busy}>
              Cancel
            </Button>
            <Button icon={Icon} onClick={confirm} waiting={busy} disabled={busy}>
              {busy ? 'Working…' : label}
            </Button>
          </>
        }
      >
        <div className="space-y-3 text-sm text-fg">
          <p className="font-mono text-xs text-fg-muted">{incident.name}</p>
          <p>{archived ? UNARCHIVE_EFFECT : ARCHIVE_EFFECT}</p>
          {error && (
            <p role="alert" className="text-sm text-high">
              {error}
            </p>
          )}
        </div>
      </Modal>
    </>
  )
}

/** The strip over an archived incident: it says so, who did it, and that it can only be read. */
export function ArchiveBanner({ incident }) {
  if (!isArchived(incident)) return null
  return (
    <div
      role="status"
      className="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-1 border-b border-med-line bg-med-soft px-6 py-2.5 text-sm text-med-fg"
    >
      <Archive className="h-4 w-4 shrink-0" aria-hidden="true" />
      <span className="font-mono font-semibold">Archived</span>
      <span className="min-w-0 flex-1">
        {incident.archivedAt ? `${formatDateTime(Date.parse(incident.archivedAt))}` : ''}
        {incident.archivedBy ? ` by ${incident.archivedBy}` : ''}
        {' · read-only. Take it out of the archive to change it.'}
      </span>
    </div>
  )
}
