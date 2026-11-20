import { useRef, useState } from 'react'
import { AlertTriangle, Download, Upload } from 'lucide-react'
import { api } from '../../../services/api.js'
import { Badge, Button } from '../../ui/index.js'

/*
 * The export of content as one file, at the foot of Settings → Backup (admin only).
 *
 * It is what "Full backup" was before 6.7: a JSON file with the incidents
 * (imported artifacts, flags and notes included), the accounts (password
 * hashes included), the audit log and the detection settings. It moves content
 * from one Nik to another. It is not a backup: it holds no file of the store,
 * no instance, no credential, no playbook, and the section above is what
 * protects the server.
 *
 * Importing such a file ADDS what this server does not have (incidents,
 * accounts, audit entries) and changes or deletes nothing that is here. Before
 * 6.7 it replaced everything, and what the file did not carry was lost. The
 * confirmation step shows what the file contains; the page reloads afterwards
 * so that every list shows what arrived.
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

export default function ContentExport() {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  // Parsed backup file waiting for the user's confirmation (null = none).
  const [pending, setPending] = useState(null)
  const fileInputRef = useRef(null)

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
        throw new Error('Not a file exported by Nik: the export of this section is expected.')
      }
      setPending({ fileName: file.name, data: parsed })
    } catch (err) {
      setError(err.message ?? 'Invalid file.')
    }
  }

  /** Send the confirmed file to the server, then reload the app. */
  const handleRestore = async () => {
    setBusy(true)
    setError(null)
    try {
      await api.post('/backup/import', pending.data)
      // A hard reload makes every context read again, with what arrived.
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
    <section aria-labelledby="content-export-title" className="space-y-4 border-t border-line pt-5">
      <div>
        <h3 id="content-export-title" className="text-sm font-semibold text-fg">
          Export as one file
        </h3>
        <p className="mt-1 max-w-prose text-sm text-fg-muted">
          What was called Full backup before 6.7. It writes the incidents, the accounts, the audit log and the detection
          settings to one JSON file, to move them to another Nik. It is not a backup of this server: it holds no file,
          no instance, no credential and no playbook. The backups above hold everything. Importing a file adds what is
          not here and changes nothing that is.
        </p>
      </div>

      <div className="max-w-xl space-y-4">
        {error && (
          <p
            role="alert"
            className="flex items-start gap-2 border border-high-line bg-high-soft px-3 py-2 text-sm text-high"
          >
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            {error}
          </p>
        )}

        {pending === null ? (
          <>
            {/* ----- Export ----- */}
            <div className="space-y-2">
              <p className="text-sm text-fg">
                Download a single JSON file with the incidents (imported artifacts, flags and notes included), the user
                accounts, the audit log and the detection settings.
              </p>
              <Button
                icon={Download}
                waiting={busy}
                disabled={busy}
                onClick={handleExport}
                className="w-full justify-center"
              >
                {busy ? 'Preparing the file…' : 'Export incidents and accounts'}
              </Button>
              <p className="text-xs text-fg-muted">The file contains password hashes: keep it as you keep a secret.</p>
            </div>

            <div className="border-t border-line" />

            {/* ----- Restore ----- */}
            <div className="space-y-2">
              <p className="text-sm text-fg">
                Import a file exported by a Nik. It shows what the file holds and asks before it adds anything.
              </p>
              <Button
                variant="secondary"
                icon={Upload}
                disabled={busy}
                onClick={() => fileInputRef.current?.click()}
                className="w-full justify-center"
              >
                Import a file…
              </Button>
              <input ref={fileInputRef} type="file" accept=".json" hidden onChange={handleFile} />
            </div>
          </>
        ) : (
          /* ----- Confirmation step ----- */
          <div className="space-y-3">
            <p className="text-sm text-fg">
              Import <strong className="text-fg">«{pending.fileName}»</strong>? The file contains:
            </p>
            <div className="flex flex-wrap gap-2">
              <Badge color="cyan">{counts.incidents} incidents</Badge>
              <Badge color="cyan">{counts.users} users</Badge>
              <Badge color="cyan">{counts.audit} audit entries</Badge>
              {pending.data.exportedAt && (
                <Badge color="slate">exported {new Date(pending.data.exportedAt).toLocaleString()}</Badge>
              )}
            </div>
            <p className="border border-line bg-canvas px-3 py-2 text-sm text-fg-muted">
              The incidents, accounts and audit entries that are not on this server are added. Nothing that is here is
              changed or deleted: an incident or an account that exists already stays as it is, and the detection
              settings of the file are taken only by a server that has none. An account that arrives signs in with the
              password it had on the other server.
            </p>
            <div className="flex justify-end gap-2">
              <Button variant="secondary" disabled={busy} onClick={() => setPending(null)}>
                Cancel
              </Button>
              <Button icon={Upload} waiting={busy} disabled={busy} onClick={handleRestore}>
                {busy ? 'Importing…' : 'Add to this server'}
              </Button>
            </div>
          </div>
        )}
      </div>
    </section>
  )
}
