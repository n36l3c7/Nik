import { Fragment, useCallback, useEffect, useRef, useState } from 'react'
import { ChevronDown, ChevronRight, Plus, X } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import {
  alreadyImported,
  canReadAgain,
  expectedOf,
  keptText,
  notRecordsText,
  missingExpected,
  needsPolling,
  readBeforeProcesses,
  readPill,
  shortHash,
  uploadText,
} from '../../domain/sourceFiles.js'
import { fromCollection, looksLikeCollection } from '../../domain/collections.js'
import { percentOf } from '../../domain/transfers.js'
import { uploadFile } from '../../lib/chunkedUpload.js'
import { openCollection } from '../../lib/collectionDialog.js'
import { holdAppDrop } from '../../lib/dropOwner.js'
import { noteEvidenceChanged } from '../../lib/useEvidenceSummary.js'
import { evidence } from '../../services/api.js'
import { Badge, Button, CopyButton, TransferBar, Wait } from '../ui/index.js'
import ParseReport from './ParseReport.jsx'

const POLL_MS = 2000
// Files sent at the same time: each one holds a session on the server, which keeps eight per person.
const PARALLEL = 2

const noMatch = () => null

/**
 * SourceFiles: the source files of a page of host evidence, as a table. Each row is a file with what
 * became of it (records kept and in the file, how it was read, its SHA-256); the report opens under it.
 * Sources the page expects and does not have are grey rows with where to find them. Files are added
 * with "Add files" or dropped anywhere on the window (a zip or a psort export is sent as it is, for the server to
 * list as a collection: its dialog opens); each is sent in parts (lib/chunkedUpload.js) with a
 * row of its own and can be cancelled.
 *
 * Props:
 *  - `incidentId`, `kind`: the section (`eventlog`, `browser`, `endpoint`, `commands`, `disk`, ...).
 *  - `filter?(source)`: keep only some of the section's files (a browser profile).
 *  - `uploadParams?`: sent with every file besides `kind` (`source`, `host`, `user`, `profile`); a function of
 *    the file (it may return a promise) when the source depends on it (a browser's History and Bookmarks).
 *  - `expected?: [{ key, label, hint }]` and `match(source) => key | null`: what the page expects.
 *  - `present?`: keys of expected sources that are satisfied without a file of their own (the records of a source
 *    that came out of a registry hive exist): they are not grey rows.
 *  - `labelOf?(source)`: the text of the Source column, when the page knows better than the expected row
 *    (the channels of an event-log file).
 *  - `showUser`: a User column in place of Source (the files whose user is given at upload: command histories).
 *  - `title`, `help` (a node: the "Where to find these files" button or dialog), `accept?` (file input).
 *  - `canWrite`: may add, read again, acknowledge and remove. `onChanged()`: after a change, and when
 *    a file ends being read, so the page can reload its counts.
 *  - `onView(source)`: opens the viewer on the file.
 * The table asks the server again every two seconds while a file is queued or being read, and not otherwise.
 */
export default function SourceFiles({
  incidentId,
  kind,
  filter = null,
  uploadParams = null,
  expected = [],
  match = noMatch,
  present = null,
  labelOf = null,
  title = 'Sources',
  help = null,
  accept,
  showUser = false,
  canWrite = false,
  onChanged = null,
  onView = null,
}) {
  const { can } = useAuth()
  const canDownload = can('evidence.download')
  const [sources, setSources] = useState(null)
  const [error, setError] = useState('')
  const [openId, setOpenId] = useState(null)
  const [reports, setReports] = useState({}) // id -> the source with its report, and the key it was read at
  const [busy, setBusy] = useState(false)
  const [items, setItems] = useState([]) // the files being sent
  const [dragging, setDragging] = useState(false)
  const inputRef = useRef(null)
  const sourcesRef = useRef([])
  const changedRef = useRef(onChanged)
  // Whatever changed also tells the counts of the app (side list, header): they come from one summary.
  changedRef.current = () => {
    noteEvidenceChanged(incidentId)
    onChanged?.()
  }
  // This page takes the drop of files: the app's own overlay stands down while it is here.
  useEffect(() => holdAppDrop(), [])

  // ---- The list ----
  const loadRef = useRef(null)
  const refresh = useCallback(
    async ({ background = false } = {}) => {
      loadRef.current?.abort()
      const controller = new AbortController()
      loadRef.current = controller
      try {
        const { sources: list } = await evidence.sources(incidentId, { kind, signal: controller.signal, background })
        if (controller.signal.aborted) return list
        // A file that was being read and is not any more: the page has new counts to show.
        const was = new Set(
          sourcesRef.current
            .filter((item) => item.state === 'queued' || item.state === 'parsing')
            .map((item) => item.id),
        )
        const ended = list.some((item) => was.has(item.id) && item.state !== 'queued' && item.state !== 'parsing')
        sourcesRef.current = list
        setSources(list)
        setError('')
        if (ended) changedRef.current?.()
        return list
      } catch (failure) {
        if (failure?.name !== 'AbortError') setError(failure?.message || 'The files could not be listed.')
        return null
      }
    },
    [incidentId, kind],
  )
  useEffect(() => {
    refresh()
    return () => loadRef.current?.abort()
  }, [refresh])

  const shown = (sources ?? []).filter((source) => (filter ? filter(source) : true))
  // Polling only while a file is queued or being read.
  useEffect(() => {
    if (!sources || !needsPolling(sources)) return undefined
    const timer = setTimeout(() => refresh({ background: true }), POLL_MS)
    return () => clearTimeout(timer)
  }, [sources, refresh])

  // ---- The report under a row: read when it opens, and again when the file changes ----
  const open = shown.find((source) => source.id === openId) ?? null
  const reportKey = open ? `${open.id}|${open.state}|${open.parsedAt}|${open.seen?.at ?? ''}` : ''
  useEffect(() => {
    if (!open) return undefined
    const controller = new AbortController()
    evidence
      .source(incidentId, open.id, { signal: controller.signal })
      .then((full) => setReports((held) => ({ ...held, [open.id]: { key: reportKey, source: full } })))
      .catch((failure) => {
        if (failure?.name !== 'AbortError') setError(failure?.message || 'The report could not be read.')
      })
    return () => controller.abort()
    // The key says when the file changed: `open` itself is a new object at every poll.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incidentId, reportKey])

  // ---- What the report's buttons do ----
  const act = (work) => async () => {
    setBusy(true)
    try {
      await work()
      await refresh()
      changedRef.current?.()
    } catch (failure) {
      // A refusal is said on the page, not thrown at nobody (these run from buttons).
      setError(failure?.message || 'That did not work.')
    } finally {
      setBusy(false)
    }
  }
  const actions = {
    onView,
    onDownload: (source) => evidence.downloadOriginal(incidentId, source),
    onAgain: (source) => act(() => evidence.readAgain(incidentId, source.id))(),
    onSeen: (source, note) => act(() => evidence.seen(incidentId, source.id, note))(),
    onForgetSeen: (source) => act(() => evidence.forgetSeen(incidentId, source.id))(),
    onRemove: (source) =>
      act(async () => {
        await evidence.remove(incidentId, source.id)
        setOpenId(null)
      })(),
  }

  // ---- Files being sent ----
  const itemsRef = useRef([])
  const controllers = useRef(new Map())
  const patch = useCallback((key, changes) => {
    itemsRef.current = itemsRef.current.map((item) => (item.key === key ? { ...item, ...changes } : item))
    setItems(itemsRef.current)
  }, [])

  const send = useCallback(
    async (item) => {
      const controller = new AbortController()
      controllers.current.set(item.key, controller)
      patch(item.key, { state: 'sending' })
      const startedAt = Date.now()
      const known = new Set(sourcesRef.current.map((source) => source.id))
      try {
        // A zip or a psort export is not this page's: the server says what it is (a collection) and its list opens.
        const auto = looksLikeCollection(item.name)
        // A function may ask the person first (a file the page cannot place): its refusal is an AbortError.
        const given = auto ? null : typeof uploadParams === 'function' ? await uploadParams(item.file) : uploadParams
        const { sourceId, kind: went } = await uploadFile(item.file, {
          incidentId,
          params: auto ? { kind: 'auto' } : { kind, ...given },
          signal: controller.signal,
          onProgress: ({ phase, sent, total }) => patch(item.key, { state: phase, sent, total }),
        })
        if (auto && went === 'collection' && sourceId) openCollection(incidentId, sourceId)
        const list = await refresh()
        const found = list?.find((source) => source.id === sourceId) ?? null
        patch(item.key, { state: 'done', sourceId, already: alreadyImported(found, known, startedAt) })
        changedRef.current?.()
      } catch (failure) {
        if (failure?.name === 'AbortError') patch(item.key, { state: 'cancelled' })
        else patch(item.key, { error: failure?.message || 'The file could not be sent.', state: 'failed' })
      } finally {
        controllers.current.delete(item.key)
        pump()
      }
    },
    // `pump` is defined below and only reads refs: it is the same function at every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [incidentId, kind, uploadParams, patch, refresh],
  )
  const pump = useCallback(() => {
    const running = itemsRef.current.filter((item) => item.state === 'sending' || item.state === 'keeping').length
    const waiting = itemsRef.current.filter((item) => item.state === 'queued')
    for (const item of waiting.slice(0, Math.max(0, PARALLEL - running))) {
      patch(item.key, { state: 'sending' })
      send(item)
    }
  }, [patch, send])

  const addFiles = useCallback(
    (fileList) => {
      const files = [...(fileList ?? [])]
      if (files.length === 0 || !canWrite) return
      const stamp = Date.now()
      const added = files.map((file, index) => ({
        key: `${stamp}-${index}-${file.name}`,
        file,
        name: file.name,
        state: 'queued',
        sent: 0,
        total: file.size,
        error: '',
      }))
      itemsRef.current = [...itemsRef.current, ...added]
      setItems(itemsRef.current)
      pump()
    },
    [canWrite, pump],
  )
  const dismiss = (key) => {
    controllers.current.get(key)?.abort()
    itemsRef.current = itemsRef.current.filter((item) => item.key !== key)
    setItems(itemsRef.current)
  }
  useEffect(
    () => () => {
      for (const controller of controllers.current.values()) controller.abort()
    },
    [],
  )

  // ---- The whole window is the drop zone ----
  useEffect(() => {
    if (!canWrite) return undefined
    let depth = 0
    const hasFiles = (event) => Array.from(event.dataTransfer?.types ?? []).includes('Files')
    const onEnter = (event) => {
      if (!hasFiles(event)) return
      depth += 1
      setDragging(true)
    }
    const onLeave = (event) => {
      if (!hasFiles(event)) return
      depth = Math.max(0, depth - 1)
      if (depth === 0) setDragging(false)
    }
    const onOver = (event) => {
      if (hasFiles(event)) event.preventDefault()
    }
    const onDrop = (event) => {
      if (!hasFiles(event)) return
      depth = 0
      setDragging(false)
      // Taken here: the app's own drop of a file anywhere stands down for what was prevented.
      event.preventDefault()
      addFiles(event.dataTransfer.files)
    }
    // Capture: before the app's handler, which would place the file by its type.
    window.addEventListener('dragenter', onEnter, true)
    window.addEventListener('dragleave', onLeave, true)
    window.addEventListener('dragover', onOver, true)
    window.addEventListener('drop', onDrop, true)
    return () => {
      window.removeEventListener('dragenter', onEnter, true)
      window.removeEventListener('dragleave', onLeave, true)
      window.removeEventListener('dragover', onOver, true)
      window.removeEventListener('drop', onDrop, true)
    }
  }, [canWrite, addFiles])

  const pick = () => inputRef.current?.click()
  const missing = missingExpected(expected, shown, match, present ?? [])
  const columns = 7

  return (
    <section aria-label={title} className="border border-line bg-panel">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-2.5">
        <h3 className="text-sm font-semibold">{title}</h3>
        <div className="flex flex-wrap items-center gap-2">
          {help}
          {canWrite && (
            <>
              <Button variant="secondary" size="sm" icon={Plus} onClick={pick}>
                Add files
              </Button>
              <input
                ref={inputRef}
                type="file"
                multiple
                accept={accept}
                className="sr-only"
                tabIndex={-1}
                aria-label="Choose files to add"
                onChange={(event) => {
                  addFiles(event.target.files)
                  event.target.value = ''
                }}
              />
            </>
          )}
        </div>
      </header>

      {error && (
        <p role="alert" className="border-b border-high-line bg-high-soft px-4 py-2 text-sm text-high-fg">
          {error}
        </p>
      )}

      {items.length > 0 && (
        <ul aria-label="Files being added" className="divide-y divide-line-soft border-b border-line">
          {items.map((item) => {
            const finished = item.state === 'done' || item.state === 'failed' || item.state === 'cancelled'
            const row = shown.find((source) => source.id === item.sourceId)
            return (
              <li key={item.key} className="flex flex-wrap items-center gap-3 px-4 py-2 text-[13px]">
                <span className="min-w-0 max-w-80 truncate font-mono" title={item.name}>
                  {item.name}
                </span>
                <span
                  className={`min-w-0 flex-1 ${item.state === 'failed' ? 'text-high-fg' : 'text-fg-muted'}`}
                  role={item.state === 'failed' ? 'alert' : undefined}
                >
                  {uploadText(item)}
                </span>
                {(item.state === 'sending' || item.state === 'keeping') && (
                  <TransferBar
                    label={`Sending ${item.name}`}
                    percent={item.state === 'keeping' ? null : percentOf({ sent: item.sent, total: item.total })}
                    className="w-40"
                  />
                )}
                {item.state === 'done' && item.already && row && (
                  <button
                    type="button"
                    onClick={() => {
                      setOpenId(row.id)
                      requestAnimationFrame(() =>
                        document.getElementById(`source-${row.id}`)?.scrollIntoView({ block: 'nearest' }),
                      )
                    }}
                    className="text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    Show its row
                  </button>
                )}
                <button
                  type="button"
                  aria-label={finished ? `Dismiss ${item.name}` : `Cancel sending ${item.name}`}
                  onClick={() => dismiss(item.key)}
                  className="p-1 text-fg-muted hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  <X className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              </li>
            )
          })}
        </ul>
      )}

      {/* `relative` keeps the screen-reader-only header inside the box: it never widens the page. */}
      <div className="relative overflow-x-auto">
        <table className="w-full min-w-[30rem] text-left text-[13px]">
          <thead className="bg-canvas">
            <tr className="border-b border-line font-mono text-xs text-fg-muted">
              <th scope="col" className="px-3 py-2 font-normal">
                {showUser ? 'User' : 'Source'}
              </th>
              <th scope="col" className="px-3 py-2 font-normal">
                File
              </th>
              <th scope="col" className="px-3 py-2 font-normal">
                Host
              </th>
              <th scope="col" className="px-3 py-2 text-right font-normal">
                Kept / in file
              </th>
              <th scope="col" className="px-3 py-2 font-normal">
                Read
              </th>
              {/* The full hash is in the report: the column takes room only on the wide screens (it keeps its place, so the report row spans it). */}
              <th
                scope="col"
                className="font-normal invisible w-0 max-w-0 overflow-hidden p-0 min-[1280px]:visible min-[1280px]:w-auto min-[1280px]:max-w-none min-[1280px]:px-3 min-[1280px]:py-2"
              >
                SHA-256
              </th>
              <th scope="col" className="px-3 py-2 font-normal">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line-soft">
            {sources === null && !error && (
              <tr>
                <td colSpan={columns} className="px-4 py-6">
                  <Wait>Loading the files…</Wait>
                </td>
              </tr>
            )}
            {sources !== null && shown.length === 0 && missing.length === 0 && (
              <tr>
                <td colSpan={columns} className="px-4 py-8 text-center font-mono text-fg-muted">
                  No files yet{canWrite ? ': add some, or drop them anywhere on this page' : ''}
                </td>
              </tr>
            )}
            {shown.map((source) => {
              const pill = readPill(source)
              const isOpen = source.id === openId
              const label = labelOf?.(source) || expectedOf(source, expected, match)?.label || source.source
              const full = reports[source.id]
              const needsFile = source.legacy || source.state === 'absent'
              return (
                <Fragment key={source.id}>
                  <tr id={`source-${source.id}`} className={isOpen ? 'bg-raised' : 'hover:bg-raised'}>
                    {showUser ? (
                      <td className="px-3 py-2 font-mono">{source.username || '—'}</td>
                    ) : (
                      <td className="px-3 py-2">{label || '—'}</td>
                    )}
                    <td
                      className="min-w-[6rem] px-3 py-2 font-mono [overflow-wrap:anywhere]"
                      title={source.filePath || source.fileName}
                    >
                      {source.fileName}
                      {fromCollection(source) && (
                        <span className="block font-sans text-xs text-fg-muted" title={fromCollection(source)}>
                          {fromCollection(source)}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 font-mono [overflow-wrap:anywhere]">{source.host || '—'}</td>
                    <td
                      className="whitespace-nowrap px-3 py-2 text-right font-mono tabular-nums"
                      title={notRecordsText(source) || undefined}
                    >
                      {keptText(source)}
                    </td>
                    <td className="px-3 py-2">
                      <Badge color={pill.color} title={pill.title} className="whitespace-normal!">
                        {pill.label}
                      </Badge>
                      {readBeforeProcesses(source) && (
                        <p className="mt-1 max-w-48 text-xs text-fg-muted">
                          Read before processes and logons were extracted
                        </p>
                      )}
                    </td>
                    <td className="whitespace-nowrap invisible w-0 max-w-0 overflow-hidden p-0 min-[1280px]:visible min-[1280px]:w-auto min-[1280px]:max-w-none min-[1280px]:px-3 min-[1280px]:py-2">
                      <span className="inline-flex items-center gap-1 font-mono text-fg-muted" title={source.sha256}>
                        {shortHash(source.sha256) || '—'}
                        {source.sha256 && (
                          <CopyButton text={source.sha256} label={`Copy the SHA-256 of ${source.fileName}`} />
                        )}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-right">
                      {needsFile && canWrite ? (
                        <Button variant="secondary" size="xs" onClick={pick}>
                          Import again
                        </Button>
                      ) : (
                        <>
                          {readBeforeProcesses(source) && canWrite && canReadAgain(source) && (
                            <Button
                              variant="secondary"
                              size="xs"
                              disabled={busy}
                              title="Read the original again: its processes and logons are added, the flags and notes stay"
                              onClick={() => actions.onAgain(source)}
                              className="mr-1"
                            >
                              Analyse again
                            </Button>
                          )}
                          <Button
                            variant="ghost"
                            size="xs"
                            icon={isOpen ? ChevronDown : ChevronRight}
                            aria-expanded={isOpen}
                            aria-controls={`report-${source.id}`}
                            onClick={() => setOpenId(isOpen ? null : source.id)}
                          >
                            Report
                          </Button>
                        </>
                      )}
                    </td>
                  </tr>
                  {isOpen && (
                    <tr id={`report-${source.id}`}>
                      <td colSpan={columns} className="bg-canvas p-3">
                        {/* w-0 min-w-full: what the report holds (its own wide tables scroll inside it) never widens this table. */}
                        <div className="w-0 min-w-full">
                          {full ? (
                            <ParseReport
                              source={{ ...source, ...full.source }}
                              canWrite={canWrite}
                              canDownload={canDownload}
                              busy={busy}
                              {...actions}
                            />
                          ) : (
                            <Wait>Reading the report…</Wait>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
            {missing.map((item) => (
              <tr key={`expected-${item.key}`} className="text-fg-muted">
                <td className="px-3 py-2">{item.label}</td>
                <td colSpan={columns - 2} className="px-3 py-2 [overflow-wrap:anywhere]">
                  Not imported{item.hint ? ` · ${item.hint}` : ''}
                </td>
                <td className="whitespace-nowrap px-3 py-2 text-right">
                  {canWrite && (
                    <Button variant="ghost" size="xs" onClick={pick}>
                      Add
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {dragging && (
        <div
          aria-hidden="true"
          className="pointer-events-none fixed inset-3 z-[85] flex items-center justify-center border-2 border-dashed border-accent bg-accent-soft/80"
        >
          <p className="font-mono text-lg text-accent-fg">drop the files: they are added to {title.toLowerCase()}</p>
        </div>
      )}
    </section>
  )
}
