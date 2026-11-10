import { useEffect, useRef, useState } from 'react'
import { AlertTriangle, Check, FileArchive, Loader2 } from 'lucide-react'
import { api, upload } from '../../../services/api.js'

/*
 * Drop zone for raw .evtx files. The browser cannot read the binary format, so
 * each file goes to the server as is (POST /incidents/{id}/upload?tab=eventlogs
 * &async=true), is parsed there in the background and merged into the
 * incident; the zone shows the upload progress, then polls the job.
 * `onDone` runs after every finished file, to reload the incident.
 */

const POLL_MS = 1000

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

async function waitForJob(jobId) {
  for (;;) {
    const job = await api.get(`/jobs/${encodeURIComponent(jobId)}`)
    if (job.status === 'done') return job.result
    if (job.status === 'error') throw new Error(job.error || 'The server could not parse the file.')
    await sleep(POLL_MS)
  }
}

const formatSize = (bytes) =>
  bytes >= 1048576 ? `${(bytes / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`

export default function EvtxUpload({ incidentId, onDone, dropped = null }) {
  const inputRef = useRef(null)
  const [isDragging, setIsDragging] = useState(false)
  const [items, setItems] = useState([]) // [{ key, name, size, state, percent, result, error }]
  const busy = items.some((item) => item.state === 'uploading' || item.state === 'parsing')

  const patch = (key, changes) => setItems((list) => list.map((it) => (it.key === key ? { ...it, ...changes } : it)))

  const handleFiles = async (fileList) => {
    const files = [...(fileList ?? [])]
    if (files.length === 0 || busy) return
    const queued = files.map((file, index) => ({
      key: `${Date.now()}-${index}`,
      file,
      name: file.name,
      size: file.size,
      state: 'queued',
      percent: 0,
    }))
    setItems(queued)
    // One at a time: a Security.evtx can be large, and the server parses each
    // file into the same incident document.
    for (const item of queued) {
      if (!/\.evtx$/i.test(item.name)) {
        patch(item.key, { state: 'error', error: 'Not an .evtx file.' })
        continue
      }
      try {
        patch(item.key, { state: 'uploading' })
        const { jobId } = await upload(
          `/incidents/${encodeURIComponent(incidentId)}/upload?tab=eventlogs&async=true`,
          item.file,
          {
            onProgress: ({ sent, total }) => patch(item.key, { percent: total ? Math.round((sent / total) * 100) : 0 }),
          },
        )
        patch(item.key, { state: 'parsing', percent: 100 })
        const result = await waitForJob(jobId)
        patch(item.key, { state: 'done', result })
        onDone?.()
      } catch (err) {
        patch(item.key, { state: 'error', error: err?.message ?? 'Upload failed.' })
      }
    }
  }

  // Files dropped elsewhere in the app and routed here (EventLogsTab).
  useEffect(() => {
    if (dropped?.files?.length) handleFiles(dropped.files)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dropped])

  const openPicker = () => {
    if (!busy) inputRef.current?.click()
  }

  return (
    <div className="flex flex-col gap-2">
      <div
        role="button"
        tabIndex={0}
        aria-label="Upload .evtx files"
        onClick={openPicker}
        onKeyDown={(event) => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault()
            openPicker()
          }
        }}
        onDragOver={(event) => {
          event.preventDefault()
          if (!busy) setIsDragging(true)
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={(event) => {
          event.preventDefault()
          setIsDragging(false)
          handleFiles(event.dataTransfer?.files)
        }}
        className={[
          'flex min-h-[140px] cursor-pointer flex-col items-center justify-center gap-2 border-2 border-dashed p-4 text-center transition-colors',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
          isDragging ? 'border-accent-strong bg-accent-soft' : 'border-line bg-canvas hover:border-accent-strong',
          busy ? 'cursor-progress' : '',
        ].join(' ')}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".evtx"
          multiple
          hidden
          onChange={(event) => {
            handleFiles(event.target.files)
            event.target.value = ''
          }}
        />
        <span className="bg-accent-soft p-2 text-accent">
          <FileArchive className="h-6 w-6" />
        </span>
        <p className="text-sm font-semibold text-fg">.evtx files</p>
        <p className="text-xs text-fg-muted">Drop one or more logs; they are parsed on the Nik server.</p>
        <p className="break-all bg-canvas px-2 py-1 font-mono text-[10px] text-fg-muted">
          C:\Windows\System32\winevt\Logs\
        </p>
      </div>

      {items.length > 0 && (
        <ul className="space-y-1 font-mono text-[11px]" aria-live="polite">
          {items.map((item) => (
            <li key={item.key} className="flex items-center gap-2">
              {item.state === 'done' ? (
                <Check className="h-3.5 w-3.5 shrink-0 text-accent" />
              ) : item.state === 'error' ? (
                <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-high" />
              ) : (
                <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-fg-muted" />
              )}
              <span className="min-w-0 flex-1 truncate text-fg" title={item.name}>
                {item.name} <span className="text-fg-subtle">{formatSize(item.size)}</span>
              </span>
              <span className={item.state === 'error' ? 'text-high' : 'text-fg-muted'}>
                {item.state === 'queued' && 'queued'}
                {item.state === 'uploading' && `uploading ${item.percent}%`}
                {item.state === 'parsing' && 'parsing on the server…'}
                {item.state === 'done' && `${(item.result?.rows ?? 0).toLocaleString('en-US')} events kept`}
                {item.state === 'error' && item.error}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
