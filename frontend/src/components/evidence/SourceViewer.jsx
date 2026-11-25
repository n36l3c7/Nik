import { useEffect, useMemo, useRef, useState } from 'react'
import { ChevronLeft, ChevronRight, X } from 'lucide-react'
import {
  PAGE_BYTES,
  copyTextOf,
  fieldRows,
  hexDump,
  neighbours,
  numberedLines,
  pageStartFor,
  pageText,
  parseOffset,
  tokenizeXml,
  viewProblem,
  whereLine,
} from '../../domain/sourceViewer.js'
import { shortHash } from '../../domain/sourceFiles.js'
import { sizeText } from '../../domain/transfers.js'
import { copyText } from '../../lib/download.js'
import { useLayer } from '../../lib/layers.js'
import { evidence } from '../../services/api.js'
import { Button, Wait } from '../ui/index.js'
import DetectionsPanel from './DetectionsPanel.jsx'

// The colour of each kind of token of an XML record; the text of the file is never given to the DOM as markup.
const XML_COLOURS = {
  tag: 'text-link',
  attr: 'text-info',
  value: 'text-med-fg',
  comment: 'text-fg-subtle',
  text: 'text-fg',
  plain: '',
}

function Xml({ text }) {
  const tokens = useMemo(() => tokenizeXml(text), [text])
  return (
    <pre className="whitespace-pre-wrap break-all p-4 font-mono text-[12.5px] leading-relaxed text-fg">
      {tokens.map((token, index) => (
        <span key={index} className={XML_COLOURS[token.type]}>
          {token.text}
        </span>
      ))}
    </pre>
  )
}

function Lines({ answer }) {
  const lines = useMemo(
    () => numberedLines(answer.text, answer.first ?? 1, answer.highlight),
    [answer.text, answer.first, answer.highlight],
  )
  return (
    <pre className="overflow-x-auto py-3 font-mono text-[12.5px] leading-relaxed text-fg">
      {lines.map((line) => (
        <div key={line.number} className={`flex gap-3 px-4 ${line.on ? 'bg-accent-soft' : ''}`}>
          <span aria-hidden="true" className="w-10 shrink-0 select-none text-right text-fg-subtle">
            {line.number}
          </span>
          <span className="whitespace-pre-wrap break-all">{line.text}</span>
        </div>
      ))}
    </pre>
  )
}

function Answer({ answer }) {
  if (answer.kind === 'xml') return <Xml text={String(answer.text ?? '')} />
  if (answer.kind === 'fields') {
    return (
      <dl className="grid grid-cols-[minmax(6rem,12rem)_minmax(0,1fr)] gap-x-4 gap-y-1.5 p-4 text-[13px]">
        {(answer.rows ?? []).map(([name, value], index) => (
          <div key={`${name}-${index}`} className="contents">
            <dt className="break-words text-fg-muted">{name}</dt>
            <dd className="m-0 whitespace-pre-wrap break-all font-mono">{value}</dd>
          </div>
        ))}
      </dl>
    )
  }
  if (answer.kind === 'text') return <Lines answer={answer} />
  return (
    <pre className="whitespace-pre-wrap break-all p-4 font-mono text-[12.5px] leading-relaxed">
      {String(answer.text ?? '')}
    </pre>
  )
}

function Choice({ value, onChange, options, label }) {
  return (
    <div role="group" aria-label={label} className="inline-flex border border-line bg-panel p-0.5">
      {options.map((option) => (
        <button
          key={option.id}
          type="button"
          aria-pressed={value === option.id}
          onClick={() => onChange(option.id)}
          className={`px-3 py-1 text-[13px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${value === option.id ? 'bg-accent-soft text-accent-fg' : 'text-fg-muted hover:text-fg'}`}
        >
          {option.label}
        </button>
      ))}
    </div>
  )
}

/** What the worker's viewer shows of one record: `state` is the answer, or the error, for `record.id`. */
function RecordView({ record, state, onPrev, onNext }) {
  const [copied, setCopied] = useState(false)
  const loading = state.id !== record.id
  const answer = loading ? null : state.answer
  const copy = async () => {
    if (!(await copyText(copyTextOf(answer)))) return
    setCopied(true)
    setTimeout(() => setCopied(false), 1200)
  }
  return (
    <div className="flex min-h-0 min-w-0 flex-1 flex-col">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line-soft px-4 py-2">
        <span className="font-mono text-xs text-fg-muted">{answer ? answer.kind : ''}</span>
        <span className="flex gap-2">
          <Button variant="secondary" size="sm" disabled={!answer} onClick={copy}>
            {copied ? 'Copied' : 'Copy'}
          </Button>
          {onPrev && (
            <Button variant="secondary" size="sm" icon={ChevronLeft} onClick={onPrev}>
              Prev
            </Button>
          )}
          {onNext && (
            <Button variant="secondary" size="sm" onClick={onNext}>
              Next
              <ChevronRight className="h-4 w-4" aria-hidden="true" />
            </Button>
          )}
        </span>
      </div>
      <div className="min-h-0 flex-1 overflow-auto" aria-live="polite">
        {loading && (
          <div className="p-4">
            <Wait>Reading the original…</Wait>
          </div>
        )}
        {!loading && state.error && (
          <div role="alert" className="p-4 text-sm">
            <p className="font-semibold">{viewProblem(state.error)}</p>
            {state.error.message && state.error.message !== viewProblem(state.error) && (
              <p className="mt-1 text-fg-muted">{state.error.message}</p>
            )}
          </div>
        )}
        {answer && (
          <>
            {answer.cut && (
              <p role="status" className="border-b border-med-line bg-med-soft px-4 py-2 text-[13px] text-med-fg">
                This is cut: the record is longer than the viewer shows. The whole file has the rest.
              </p>
            )}
            <Answer answer={answer} />
          </>
        )}
      </div>
    </div>
  )
}

/** The bytes of the original, a page of 64 KiB at a time, as text or as hex. */
function FileView({ incidentId, source, start: first = 0 }) {
  const [as, setAs] = useState('text')
  const [start, setStart] = useState(first)
  const [jump, setJump] = useState('')
  const [jumpError, setJumpError] = useState('')
  const [state, setState] = useState({ key: '', page: null, error: null })
  const key = `${source.id}|${as}|${start}`
  useEffect(() => {
    const controller = new AbortController()
    evidence
      .sourcePage(incidentId, source.id, { offset: start, length: PAGE_BYTES, as, signal: controller.signal })
      .then((page) => setState({ key, page, error: null }))
      .catch((error) => {
        if (error?.name !== 'AbortError') setState({ key, page: null, error })
      })
    return () => controller.abort()
  }, [incidentId, source.id, as, start, key])

  const loading = state.key !== key
  const page = loading ? null : state.page
  const size = page?.size ?? source.size ?? 0
  const around = neighbours(start, size)
  const [copied, setCopied] = useState(false)
  const body = useMemo(() => (page && as === 'hex' ? hexDump(page.data, page.offset) : (page?.data ?? '')), [page, as])

  const go = (event) => {
    event.preventDefault()
    const offset = parseOffset(jump)
    if (offset === null) {
      setJumpError('Type an offset: 0x1A00 for hex, or a decimal number')
      return
    }
    setJumpError('')
    setStart(pageStartFor(offset, size || offset + 1))
  }
  const copy = async () => {
    if (!(await copyText(body))) return
    setCopied(true)
    setTimeout(() => setCopied(false), 1200)
  }

  return (
    <div className="flex min-h-0 min-w-0 flex-1 flex-col">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line-soft px-4 py-2">
        <Choice
          label="Show the bytes as"
          value={as}
          onChange={setAs}
          options={[
            { id: 'text', label: 'Text' },
            { id: 'hex', label: 'Hex' },
          ]}
        />
        <form onSubmit={go} className="flex items-center gap-2">
          <label className="sr-only" htmlFor="viewer-offset">
            Go to offset
          </label>
          <input
            id="viewer-offset"
            value={jump}
            onChange={(event) => setJump(event.target.value)}
            placeholder="Go to offset: 0x1A00 or 6656"
            aria-invalid={Boolean(jumpError) || undefined}
            className="w-56 border border-line bg-canvas px-2 py-1 font-mono text-[13px] text-fg placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          />
          <Button type="submit" variant="secondary" size="sm">
            Go
          </Button>
        </form>
        <span className="flex gap-2">
          <Button variant="secondary" size="sm" disabled={!page} onClick={copy}>
            {copied ? 'Copied' : 'Copy'}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            icon={ChevronLeft}
            disabled={around.previous === null}
            onClick={() => setStart(around.previous)}
          >
            Previous page
          </Button>
          <Button variant="secondary" size="sm" disabled={around.next === null} onClick={() => setStart(around.next)}>
            Next page
            <ChevronRight className="h-4 w-4" aria-hidden="true" />
          </Button>
        </span>
      </div>
      {jumpError && (
        <p role="alert" className="border-b border-line-soft px-4 py-1.5 text-[13px] text-high-fg">
          {jumpError}
        </p>
      )}
      <p className="border-b border-line-soft px-4 py-1.5 font-mono text-xs text-fg-muted" aria-live="polite">
        {page
          ? `${pageText(page.offset, page.length, page.size)} · ${sizeText(page.size)}`
          : source.size
            ? sizeText(source.size)
            : ''}
      </p>
      <div className="min-h-0 flex-1 overflow-auto">
        {loading && (
          <div className="p-4">
            <Wait>Reading the original…</Wait>
          </div>
        )}
        {!loading && state.error && (
          <div role="alert" className="p-4 text-sm">
            <p className="font-semibold">
              {state.error.status === 404 ? 'This file has no original to show' : viewProblem(state.error)}
            </p>
            {state.error.message && <p className="mt-1 text-fg-muted">{state.error.message}</p>}
          </div>
        )}
        {page && (
          <pre
            className={`${as === 'hex' ? 'whitespace-pre' : 'whitespace-pre-wrap [overflow-wrap:anywhere]'} p-4 font-mono text-[12.5px] leading-relaxed text-fg`}
            tabIndex={0}
            aria-label="Bytes of the original"
          >
            {body}
          </pre>
        )}
      </div>
    </div>
  )
}

/**
 * SourceViewer: a drawer from the right that shows the original behind a record, or the file whole.
 *
 *  - "This record": at the left what Nik extracted (`record.fields`, pairs or an object; without them
 *    the record is read from the server and its `data` is shown), at the right what the worker's viewer
 *    answers for it (`xml`, `fields`, `text` or `json`), cut notice included.
 *  - "Whole file": the bytes of the original as text or hex, 64 KiB a page, with a way to go to an offset.
 *
 * Props: `incidentId`; `source` (`{ id, fileName, sha256?, size? }`); `record?` (`{ id, fields? }`: no
 * record, no "This record" tab); `onClose`; `onPrev?`, `onNext?` (the neighbours of the record in the list
 * it was opened from). The content of a file is always drawn as text: nothing of it is HTML.
 */
export default function SourceViewer({ incidentId, source, record = null, onClose, onPrev = null, onNext = null }) {
  const ref = useRef(null)
  useLayer(ref, { open: true, onClose })
  const [mode, setMode] = useState(record ? 'record' : 'file')
  const [extracted, setExtracted] = useState(null) // the record read from the server: its fields, when it came without, and its detections
  const given = record?.fields
  const recordId = record?.id

  // The record from the server: its `data` (the fields, when the caller gave none) and its detections.
  useEffect(() => {
    if (recordId === undefined) return undefined
    const controller = new AbortController()
    evidence
      .record(incidentId, recordId, { signal: controller.signal })
      .then((full) =>
        setExtracted({
          id: recordId,
          detections: full.detections ?? [],
          rows: fieldRows([
            ['summary', full.summary],
            ['type', full.type],
            ['host', full.host],
            ['user', full.username],
            ...Object.entries(full.data ?? {}),
          ]),
        }),
      )
      .catch(() => setExtracted({ id: recordId, rows: [], detections: [] }))
    return () => controller.abort()
  }, [incidentId, recordId])
  const rows = given ? fieldRows(given) : extracted?.id === recordId ? extracted.rows : null
  const detections = extracted?.id === recordId ? extracted.detections : null

  // What the worker's viewer shows of the record: the right pane, and the title and place in the header.
  const [view, setView] = useState({ id: null, answer: null, error: null })
  useEffect(() => {
    if (recordId === undefined) return undefined
    const controller = new AbortController()
    evidence
      .view(incidentId, recordId, { signal: controller.signal })
      .then((answer) => setView({ id: recordId, answer, error: null }))
      .catch((error) => {
        if (error?.name !== 'AbortError') setView({ id: recordId, answer: null, error })
      })
    return () => controller.abort()
  }, [incidentId, recordId])
  const seen = view.id === recordId ? view.answer : null
  const header = seen ? [seen.title, whereLine(seen.where)] : []

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-sunken/60"
      onMouseDown={(event) => event.target === event.currentTarget && onClose?.()}
    >
      <aside
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label="Source of the record"
        tabIndex={-1}
        className="flex h-full w-full max-w-[900px] flex-col border-l border-line bg-canvas shadow-2xl focus:outline-none"
      >
        <header className="flex items-center justify-between gap-3 border-b border-line px-5 py-3">
          <div className="min-w-0">
            <h2 className="text-base font-semibold">{mode === 'record' ? 'Source of the record' : 'Source file'}</h2>
            <p className="truncate font-mono text-xs text-fg-muted" title={source.fileName}>
              {[source.fileName, ...(mode === 'record' ? header : [])].filter(Boolean).join(' · ')}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {record && (
              <Choice
                label="What to show"
                value={mode}
                onChange={setMode}
                options={[
                  { id: 'record', label: 'This record' },
                  { id: 'file', label: 'Whole file' },
                ]}
              />
            )}
            <Button variant="ghost" size="sm" icon={X} aria-label="Close" onClick={onClose} />
          </div>
        </header>

        <div className="flex min-h-0 flex-1">
          {mode === 'record' && record ? (
            <>
              <section
                aria-label="What Nik extracted"
                className="hidden w-[300px] shrink-0 overflow-y-auto border-r border-line sm:block"
              >
                <DetectionsPanel detections={detections} />
                <h3 className="border-b border-line-soft px-4 py-3 text-sm font-semibold">What Nik extracted</h3>
                {rows === null ? (
                  <div className="p-4">
                    <Wait>Loading…</Wait>
                  </div>
                ) : (
                  <dl className="grid grid-cols-[5.5rem_minmax(0,1fr)] gap-x-3 gap-y-2 p-4 text-[13px]">
                    {rows.map(([name, value], index) => (
                      <div key={`${name}-${index}`} className="contents">
                        <dt className="break-words text-fg-muted">{name}</dt>
                        <dd className="m-0 break-all font-mono">{value}</dd>
                      </div>
                    ))}
                  </dl>
                )}
              </section>
              <RecordView record={record} state={view} onPrev={onPrev} onNext={onNext} />
            </>
          ) : (
            <FileView incidentId={incidentId} source={source} />
          )}
        </div>

        <footer className="flex flex-wrap gap-x-6 gap-y-1 border-t border-line px-5 py-2.5 text-xs text-fg-muted">
          <span>Original kept on the server, read-only</span>
          {source.sha256 && (
            <span className="font-mono" title={source.sha256}>
              SHA-256 {shortHash(source.sha256, 16)}
            </span>
          )}
          {source.size ? <span>{sizeText(source.size)}</span> : null}
        </footer>
      </aside>
    </div>
  )
}
