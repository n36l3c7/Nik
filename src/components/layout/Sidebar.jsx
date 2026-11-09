import { useMemo, useRef, useState } from 'react'
import { AlertTriangle, DatabaseBackup, Download, Info, Plus, ScrollText, Trash2, Upload, Users, X } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { formatRelative } from '../../utils/time.js'
import { getOsById } from '../../config/os.js'
import { Button, MicroSkull, Modal } from '../ui/index.js'
import BackupModal from '../backup/BackupModal.jsx'

/*
 * ============================================================================
 * SIDEBAR — incident navigation and management
 * ============================================================================
 *
 * Contains: brand, "New incident" button (opens the modal owned by App via
 * the `onCreateIncident` callback), the incident list sorted by last update
 * with per-row actions (export / delete), JSON import from file, and a footer
 * with quick access to the Audit log and User management.
 *
 * Note: incidents are NOT renamed here — their identity (host/username) is
 * edited in the Summary tab, which recomputes the display name.
 */

/** Compact icon-button used for the per-row actions of the incident list. */
function RowAction({ icon: Icon, label, danger = false, busy = false, onClick }) {
  return (
    <button
      type="button"
      title={label}
      aria-label={label}
      aria-busy={busy || undefined}
      disabled={busy}
      onClick={onClick}
      className={[
        'p-1.5 transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
        danger ? 'text-fg-muted hover:bg-high-soft hover:text-high' : 'text-fg-muted hover:bg-raised hover:text-fg',
      ].join(' ')}
    >
      {busy ? <MicroSkull className="text-[10px] leading-none" /> : <Icon className="h-3.5 w-3.5" />}
    </button>
  )
}

/**
 * Application sidebar.
 * @param {{
 *   onCreateIncident: () => void,  // opens the "New incident" modal owned by App
 *   onOpenAudit: () => void,       // opens the Audit log modal
 *   onOpenUsers: () => void,       // opens the User management modal
 *   width?: number,                // pixel width (resizable), defaults to 288
 * }} props
 */
export default function Sidebar({ onCreateIncident, onOpenAudit, onOpenUsers, width = 288 }) {
  const { incidents, activeIncidentId, selectIncident, deleteIncident, exportIncident, importIncidentFromFile } =
    useIncidents()
  const { currentUser } = useAuth()
  const isAdmin = currentUser?.role === 'admin'

  // Incident pending deletion confirmation (null = modal closed).
  const [deleteTarget, setDeleteTarget] = useState(null)
  // Incident being exported (its document may need fetching first).
  const [exportingId, setExportingId] = useState(null)

  // Full-backup modal (admin only).
  const [backupOpen, setBackupOpen] = useState(false)

  // Import-from-file state: dismissible error shown in the sidebar + loading.
  const [importError, setImportError] = useState(null)
  const [importing, setImporting] = useState(false)
  const fileInputRef = useRef(null)

  // List ordered by last update (most recent first).
  const sortedIncidents = useMemo(
    () => [...incidents].sort((a, b) => Date.parse(b.updatedAt) - Date.parse(a.updatedAt)),
    [incidents],
  )

  /** Confirm permanent deletion of the incident. */
  const handleDeleteConfirm = () => {
    deleteIncident(deleteTarget.id)
    setDeleteTarget(null)
  }

  /** Handle selection of the JSON file to import. */
  const handleImportFile = async (event) => {
    const file = event.target.files?.[0]
    // Reset the input so the same file can be imported again right after.
    event.target.value = ''
    if (!file) return
    setImporting(true)
    setImportError(null)
    try {
      await importIncidentFromFile(file)
    } catch (error) {
      setImportError(error.message)
    } finally {
      setImporting(false)
    }
  }

  return (
    <aside style={{ width }} className="flex h-full shrink-0 flex-col border-r border-line bg-sunken">
      {/* ----- Brand ----- */}
      <div className="flex items-center gap-3 border-b border-line px-4 py-4">
        <span aria-hidden="true" className="shrink-0 bg-accent px-2 py-1 font-mono text-sm font-extrabold text-canvas">
          &gt;_
        </span>
        <div className="min-w-0">
          <p className="font-mono text-lg font-extrabold leading-tight tracking-widest text-fg">nik</p>
          <p className="truncate text-[11px] text-fg-muted">forensic analysis platform</p>
        </div>
      </div>

      {/* ----- New incident ----- */}
      <div className="px-4 pt-4">
        <Button icon={Plus} className="w-full justify-center" onClick={onCreateIncident}>
          New incident
        </Button>
      </div>

      {/* ----- Incident list (independent scroll) ----- */}
      <nav aria-label="Incidents" className="mt-4 flex-1 overflow-y-auto px-3 pb-2">
        <p className="px-1 pb-2 font-mono text-[11px] tracking-wider text-fg-muted">INCIDENTS · {incidents.length}</p>

        {sortedIncidents.length === 0 ? (
          <p className="px-1 text-sm text-fg-muted">No incidents yet: create a new one or import an existing file.</p>
        ) : (
          <ul className="space-y-1">
            {sortedIncidents.map((incident) => {
              const isActive = incident.id === activeIncidentId
              const os = getOsById(incident.os)
              const OsIcon = os?.icon
              return (
                <li key={incident.id} className="group relative">
                  {/* Clickable row: selects the incident */}
                  <button
                    type="button"
                    onClick={() => selectIncident(incident.id)}
                    aria-current={isActive ? 'true' : undefined}
                    className={[
                      'w-full px-3 py-2 text-left transition-colors',
                      'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                      isActive ? 'bg-panel shadow-[inset_2px_0_0_var(--color-accent)]' : 'hover:bg-panel/60',
                    ].join(' ')}
                  >
                    <span
                      className={[
                        'flex items-center gap-1.5 truncate pr-14 font-mono text-[13px] font-semibold',
                        isActive ? 'text-fg' : 'text-fg/90',
                      ].join(' ')}
                    >
                      {OsIcon && <OsIcon className={`h-3.5 w-3.5 shrink-0 ${os.accent}`} aria-label={os.label} />}
                      <span className="truncate">{incident.name}</span>
                    </span>
                    <span className="block text-[11px] text-fg-muted">
                      updated {formatRelative(incident.updatedAt)}
                    </span>
                  </button>

                  {/* Per-row actions: visible on hover / keyboard focus.
                      They live OUTSIDE the selection button to avoid nested
                      <button> elements (invalid HTML). No rename here —
                      incidents are edited from the Summary tab. */}
                  <div className="absolute right-2 top-1/2 flex -translate-y-1/2 gap-0.5 opacity-0 transition-opacity group-focus-within:opacity-100 group-hover:opacity-100">
                    <RowAction
                      icon={Download}
                      label={`Export incident "${incident.name}"`}
                      busy={exportingId === incident.id}
                      onClick={async () => {
                        setExportingId(incident.id)
                        try {
                          await exportIncident(incident.id)
                        } finally {
                          setExportingId(null)
                        }
                      }}
                    />
                    <RowAction
                      icon={Trash2}
                      label={`Delete incident "${incident.name}"`}
                      danger
                      onClick={() => setDeleteTarget(incident)}
                    />
                  </div>
                </li>
              )
            })}
          </ul>
        )}
      </nav>

      {/* ----- Import + tools + informational footer ----- */}
      <div className="space-y-2.5 border-t border-line px-4 py-3">
        {/* Import error: dismissible red banner */}
        {importError && (
          <div
            role="alert"
            className="flex items-start gap-2 border border-high-line bg-high-soft px-2.5 py-2 text-xs text-high-fg"
          >
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span className="flex-1">{importError}</span>
            <button
              type="button"
              aria-label="Dismiss error message"
              onClick={() => setImportError(null)}
              className="p-0.5 hover:bg-high-line/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        )}

        <Button
          variant="secondary"
          icon={Upload}
          className="w-full justify-center"
          disabled={importing}
          onClick={() => fileInputRef.current?.click()}
        >
          {importing ? 'Importing…' : 'Import incident'}
        </Button>
        <input ref={fileInputRef} type="file" accept=".json" hidden onChange={handleImportFile} />

        {/* Quick access to the Audit log and User management modals */}
        <div className="flex gap-2">
          <Button variant="ghost" size="sm" icon={ScrollText} className="flex-1 justify-center" onClick={onOpenAudit}>
            Audit log
          </Button>
          <Button variant="ghost" size="sm" icon={Users} className="flex-1 justify-center" onClick={onOpenUsers}>
            Users
          </Button>
        </div>

        {/* Full backup (export/restore everything) — admin only */}
        {isAdmin && (
          <Button
            variant="ghost"
            size="sm"
            icon={DatabaseBackup}
            className="w-full justify-center"
            onClick={() => setBackupOpen(true)}
          >
            Full backup
          </Button>
        )}

        <p className="flex items-start gap-1.5 text-[11px] text-fg-muted">
          <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          Artifacts are parsed locally; cases are stored on the Nik server
        </p>
      </div>

      {/* ----- Full-backup modal (admin only) ----- */}
      {isAdmin && <BackupModal open={backupOpen} onClose={() => setBackupOpen(false)} />}

      {/* ----- Delete confirmation modal ----- */}
      <Modal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        title="Delete incident"
        footer={
          <>
            <Button variant="secondary" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button variant="danger" icon={Trash2} onClick={handleDeleteConfirm}>
              Delete permanently
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="text-sm text-fg">
            You are about to delete the incident <strong className="font-mono">«{deleteTarget?.name}»</strong>.
          </p>
          <p className="flex items-start gap-2 border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            This action is irreversible: every imported artifact and analysis in this incident will be lost. Export the
            incident first if you want to keep a copy.
          </p>
        </div>
      </Modal>
    </aside>
  )
}
