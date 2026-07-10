import { useRef, useState } from 'react'
import {
  AlertTriangle,
  DatabaseBackup,
  Download,
  Upload,
} from 'lucide-react'
import { api } from '../../services/api.js'
import { Badge, Button, Modal } from '../ui/index.js'

/*
 * ============================================================================
 * FULL BACKUP — export / restore the entire platform (admin only)
 * ============================================================================
 *
 * Export downloads a single JSON envelope with EVERYTHING stored server-side:
 * users (password hashes included), incidents with all imported artifacts,
 * flags and notes, the audit log and the shared settings.
 *
 * Restore replaces ALL current data with the file's content, so it sits behind
 * an explicit confirmation step that shows what the file contains. The backend
 * keeps the current admin signed in across the restore; a full page reload
 * afterwards makes every context refetch the restored data.
 */

/** Trigger a client-side download of `data` as a pretty-printed JSON file. */
function downloadJson(fileName, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: 'application/json',
  })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = fileName
  link.click()
  URL.revokeObjectURL(url)
}

export default function BackupModal({ open, onClose }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  // Parsed backup file waiting for the user's confirmation (null = none).
  const [pending, setPending] = useState(null)
  const fileInputRef = useRef(null)

  const reset = () => {
    setError(null)
    setPending(null)
    setBusy(false)
  }

  const handleClose = () => {
    if (busy) return
    reset()
    onClose()
  }

  /** Download the full backup produced by the server. */
  const handleExport = async () => {
    setBusy(true)
    setError(null)
    try {
      const data = await api.get('/backup/export')
      const stamp = new Date().toISOString().slice(0, 16).replace(/[T:]/g, '-')
      downloadJson(`nik-backup-${stamp}.json`, data)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  /** Read and validate the selected file, then ask for confirmation. */
  const handleFile = async (event) => {
    const file = event.target.files?.[0]
    event.target.value = '' // allow re-selecting the same file
    if (!file) return
    setError(null)
    try {
      const parsed = JSON.parse(await file.text())
      // Accept the new 'Nik' envelope and legacy 'CSAP' exports.
      if ((parsed?.app !== 'Nik' && parsed?.app !== 'CSAP') || parsed?.type !== 'backup') {
        throw new Error(
          'Not a Nik backup file: a full-backup export is expected.',
        )
      }
      setPending({ fileName: file.name, data: parsed })
    } catch (err) {
      setError(err.message ?? 'Invalid file.')
    }
  }

  /** Send the confirmed backup to the server, then reload the app. */
  const handleRestore = async () => {
    setBusy(true)
    setError(null)
    try {
      await api.post('/backup/import', pending.data)
      // The backend kept our session alive: a hard reload makes every context
      // refetch the restored data from scratch.
      window.location.reload()
    } catch (err) {
      setError(err.message)
      setBusy(false)
    }
  }

  const counts = pending
    ? {
        users: pending.data.users?.length ?? 0,
        incidents: pending.data.incidents?.length ?? 0,
        audit: pending.data.audit?.length ?? 0,
      }
    : null

  return (
    <Modal open={open} onClose={handleClose} title="Full backup">
      <div className="space-y-4">
        {error && (
          <p
            role="alert"
            className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/60 dark:text-red-400"
          >
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            {error}
          </p>
        )}

        {pending === null ? (
          <>
            {/* ----- Export ----- */}
            <div className="space-y-2">
              <p className="text-sm text-slate-700 dark:text-slate-300">
                Download a single JSON file with <strong>everything</strong>{' '}
                stored on the server: incidents (imported artifacts, flags and
                notes included), user accounts, the audit log and the detection
                settings.
              </p>
              <Button
                icon={Download}
                disabled={busy}
                onClick={handleExport}
                className="w-full justify-center"
              >
                {busy ? 'Preparing backup…' : 'Export full backup'}
              </Button>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                The file contains password hashes: store it like any database
                dump.
              </p>
            </div>

            <div className="border-t border-slate-200 dark:border-slate-800" />

            {/* ----- Restore ----- */}
            <div className="space-y-2">
              <p className="text-sm text-slate-700 dark:text-slate-300">
                Restore a backup file. You will be asked to confirm before
                anything is touched.
              </p>
              <Button
                variant="secondary"
                icon={Upload}
                disabled={busy}
                onClick={() => fileInputRef.current?.click()}
                className="w-full justify-center"
              >
                Restore from backup…
              </Button>
              <input
                ref={fileInputRef}
                type="file"
                accept=".json"
                hidden
                onChange={handleFile}
              />
            </div>
          </>
        ) : (
          /* ----- Confirmation step ----- */
          <div className="space-y-3">
            <p className="text-sm text-slate-700 dark:text-slate-300">
              Restore{' '}
              <strong className="text-slate-900 dark:text-white">
                «{pending.fileName}»
              </strong>
              ? The file contains:
            </p>
            <div className="flex flex-wrap gap-2">
              <Badge color="cyan">{counts.incidents} incidents</Badge>
              <Badge color="cyan">{counts.users} users</Badge>
              <Badge color="cyan">{counts.audit} audit entries</Badge>
              {pending.data.exportedAt && (
                <Badge color="slate">
                  exported {new Date(pending.data.exportedAt).toLocaleString()}
                </Badge>
              )}
            </div>
            <p className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/60 dark:text-red-400">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              This replaces <strong>all</strong> current data on the server —
              every incident, user account, audit entry and setting. Export a
              backup of the current state first if you may need it again.
            </p>
            <div className="flex justify-end gap-2">
              <Button
                variant="secondary"
                disabled={busy}
                onClick={() => setPending(null)}
              >
                Cancel
              </Button>
              <Button
                variant="danger"
                icon={DatabaseBackup}
                disabled={busy}
                onClick={handleRestore}
              >
                {busy ? 'Restoring…' : 'Replace everything'}
              </Button>
            </div>
          </div>
        )}
      </div>
    </Modal>
  )
}
