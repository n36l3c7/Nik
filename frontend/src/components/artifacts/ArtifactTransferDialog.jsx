import { useEffect, useRef, useState } from 'react'
import { Download, Upload } from 'lucide-react'
import { postForBlob, upload } from '../../services/api.js'
import { saveBlob } from '../../lib/download.js'
import { Button, Modal } from '../ui/index.js'

/*
 * Artifacts out of this Nik and into another.
 *
 * Export: the analyses always; the original files only when asked, at each
 * export, because they are live malware (they travel in an AES-encrypted zip,
 * password "infected"). Import (admins): the artifacts this server does not
 * have are added; nothing is run.
 */

/**
 * @param {{
 *   request: { mode: 'export', ids: string[], label: string } | { mode: 'import' } | null,
 *   onClose: () => void,
 *   onImported: (result: object) => void,
 * }} props
 */
export default function ArtifactTransferDialog({ request, onClose, onImported }) {
  const [files, setFiles] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)
  const input = useRef(null)

  useEffect(() => {
    setFiles(false)
    setError(null)
    setResult(null)
  }, [request])

  if (!request) return null
  const run = async (work) => {
    setBusy(true)
    setError(null)
    try {
      await work()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  if (request.mode === 'import')
    return (
      <Modal
        open
        onClose={onClose}
        title="Import artifacts"
        footer={
          result ? (
            <Button onClick={onClose}>Close</Button>
          ) : (
            <>
              <Button variant="ghost" onClick={onClose}>
                Cancel
              </Button>
              <Button icon={Upload} disabled={busy} onClick={() => input.current?.click()}>
                {busy ? 'Importing…' : 'Choose the archive'}
              </Button>
            </>
          )
        }
      >
        <input
          ref={input}
          type="file"
          hidden
          accept=".zip,application/zip"
          aria-label="Artifact archive"
          onChange={(event) => {
            const file = event.target.files?.[0]
            event.target.value = ''
            if (file)
              run(async () => {
                const imported = await upload('/artifacts/import', file)
                setResult(imported)
                onImported(imported)
              })
          }}
        />
        {result ? (
          <div className="space-y-2" role="status">
            <p>
              <b>{result.added}</b> added, <b>{result.existing}</b> already here
              {result.skipped.length > 0 && (
                <>
                  , <b>{result.skipped.length}</b> skipped
                </>
              )}
              .
            </p>
            {result.skipped.length > 0 && (
              <ul className="max-h-40 overflow-y-auto border border-line bg-canvas p-2 font-mono text-xs">
                {result.skipped.map((item, index) => (
                  <li key={index}>
                    {item.name}: <span className="text-fg-muted">{item.reason}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        ) : (
          <div className="space-y-2">
            <p>
              Choose a <span className="font-mono">nik-artifacts-….zip</span> exported from Nik. The artifacts this
              server does not have are added with their analyses and tags; the ones it has are left as they are.
            </p>
            <p className="text-fg-muted">
              A file is stored only when its SHA-256 is the one its artifact is named by. Nothing is run and no analysis
              is started.
            </p>
          </div>
        )}
        {error && (
          <p role="alert" className="mt-3 font-mono text-xs text-high">
            {error}
          </p>
        )}
      </Modal>
    )

  const count = request.ids.length
  return (
    <Modal
      open
      onClose={onClose}
      title={`Export ${count === 1 ? request.label : `${count} artifacts`}`}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            icon={Download}
            disabled={busy}
            onClick={() =>
              run(async () => {
                const blob = await postForBlob('/artifacts/export', { ids: request.ids, files })
                const day = new Date().toISOString().slice(0, 10)
                saveBlob(blob, `nik-artifacts-${day}${files ? '-with-files' : ''}.zip`)
                onClose()
              })
            }
          >
            {busy ? 'Preparing…' : 'Download the archive'}
          </Button>
        </>
      }
    >
      <fieldset className="space-y-2">
        <legend className="mb-1 font-mono text-[11px] uppercase tracking-wider text-fg-muted">What goes in</legend>
        <label className="flex items-start gap-2">
          <input
            type="radio"
            name="artifact-export"
            className="mt-1"
            checked={!files}
            onChange={() => setFiles(false)}
          />
          <span>
            Analyses only
            <span className="block text-xs text-fg-muted">
              Verdicts, indicators, tags and everything the analysis tabs show. Safe to send: no file is in it.
            </span>
          </span>
        </label>
        <label className="flex items-start gap-2">
          <input type="radio" name="artifact-export" className="mt-1" checked={files} onChange={() => setFiles(true)} />
          <span>
            Analyses and the original files
            <span className="block text-xs text-fg-muted">
              The files go in an encrypted zip inside the archive, password{' '}
              <span className="font-mono text-fg">infected</span>.
            </span>
          </span>
        </label>
      </fieldset>
      {files && (
        <p className="mt-3 border-l-2 border-high-line bg-high-soft/50 px-3 py-2 text-sm">
          These files are live malware. Keep the archive private, and never open what is in it outside an analysis
          machine.
        </p>
      )}
      {error && (
        <p role="alert" className="mt-3 font-mono text-xs text-high">
          {error}
        </p>
      )}
    </Modal>
  )
}
