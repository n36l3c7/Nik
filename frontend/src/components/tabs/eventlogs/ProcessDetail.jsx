import { useEffect, useState } from 'react'
import { FileSearch, ListTree, X } from 'lucide-react'
import { Button, CopyButton, Wait } from '../../ui/index.js'
import DetectionsPanel from '../../evidence/DetectionsPanel.jsx'
import LevelBadge from '../../evidence/LevelBadge.jsx'
import { nameOf, ranText } from '../../../domain/processTree.js'
import { formatDateTime } from '../../../lib/time.js'
import { evidence } from '../../../services/api.js'

/*
 * The detail of one process (a drawer beside the tree, not a dialog: the arrows of the tree keep working):
 * every field the log gave, the hashes with their copy buttons, its ancestors and its children (each one
 * opens its own detail), and the detections of its record. "Open the event" opens the original record in
 * the Source viewer. What the tree answer gives (ancestors, children) is read here, for this process only.
 */

const CHILDREN_SHOWN = 20

function Field({ label, children, copy = '' }) {
  if (children === '' || children === null || children === undefined) return null
  return (
    <div className="contents">
      <dt className="text-fg-muted">{label}</dt>
      <dd className="m-0 flex min-w-0 items-start gap-1 break-all font-mono text-[12.5px]">
        <span className="min-w-0 flex-1 whitespace-pre-wrap">{children}</span>
        {copy && <CopyButton text={copy} label={`Copy ${label.toLowerCase()}`} />}
      </dd>
    </div>
  )
}

/** A process of the lists of the drawer: its name, as a button that opens its detail. */
function Link({ process, onSelect, indent = 0 }) {
  return (
    <li style={indent ? { paddingLeft: `${indent}px` } : undefined}>
      <button
        type="button"
        onClick={() => onSelect(process)}
        title={[process.image, process.commandLine].filter(Boolean).join('\n')}
        className="flex w-full items-center gap-2 px-1 py-0.5 text-left font-mono text-xs text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        <span className="min-w-0 truncate">{nameOf(process)}</span>
        <LevelBadge level={process.level} />
        <span className="ml-auto shrink-0 text-fg-subtle">pid {process.pid ?? '—'}</span>
      </button>
    </li>
  )
}

/**
 * @param {{ incidentId: string, process: object, onClose: () => void, onSelect: (process: object) => void,
 *   onOpenEvent: (process: object) => void, onShowInTree: (process: object) => void }} props
 */
export default function ProcessDetail({ incidentId, process, onClose, onSelect, onOpenEvent, onShowInTree }) {
  const [around, setAround] = useState({ id: null, answer: null, error: '' })
  const [record, setRecord] = useState({ id: null, detections: [] })
  const { id, recordId } = process

  useEffect(() => {
    const controller = new AbortController()
    evidence
      .processTree(incidentId, id, { up: 32, down: 1, signal: controller.signal })
      .then((answer) => setAround({ id, answer, error: '' }))
      .catch((failure) => {
        if (failure?.name !== 'AbortError') setAround({ id, answer: null, error: failure?.message || 'Not read' })
      })
    return () => controller.abort()
  }, [incidentId, id])

  // The detections are the ones of the record of the process (the same the Events row shows).
  useEffect(() => {
    if (recordId === null || recordId === undefined) return undefined
    const controller = new AbortController()
    evidence
      .record(incidentId, recordId, { signal: controller.signal })
      .then((full) => setRecord({ id: recordId, detections: full.detections ?? [] }))
      .catch(() => setRecord({ id: recordId, detections: [] }))
    return () => controller.abort()
  }, [incidentId, recordId])

  const ready = around.id === id
  const answer = ready ? around.answer : null
  const ancestors = answer?.ancestors ?? []
  const children = (answer?.descendants ?? []).filter((item) => item.depth === 1)
  const hashes = Object.entries(process.hashes ?? {})
  const ran = ranText(process.startTs, process.endTs)
  const detections = record.id === recordId ? record.detections : []

  return (
    <aside aria-label={`Process ${nameOf(process)}`} className="flex min-w-0 flex-col border border-line bg-panel">
      <header className="flex items-start justify-between gap-2 border-b border-line px-4 py-3">
        <div className="min-w-0">
          <h3 className="m-0 truncate font-mono text-sm font-semibold" title={process.image}>
            {nameOf(process)}
          </h3>
          <p className="m-0 mt-1 flex flex-wrap items-center gap-2 text-xs text-fg-muted">
            <LevelBadge level={process.level} />
            <span>
              pid {process.pid ?? '—'} · {process.host || 'no host'}
            </span>
          </p>
        </div>
        <Button variant="ghost" size="sm" icon={X} aria-label="Close the detail" onClick={onClose} />
      </header>
      <div className="flex flex-wrap gap-2 border-b border-line-soft px-4 py-2">
        <Button
          variant="secondary"
          size="xs"
          icon={FileSearch}
          disabled={recordId === null || recordId === undefined}
          title="Open the original record of this process in the Source viewer"
          onClick={() => onOpenEvent(process)}
        >
          Open the event
        </Button>
        <Button variant="ghost" size="xs" icon={ListTree} onClick={() => onShowInTree(process)}>
          Show in the tree
        </Button>
      </div>

      <DetectionsPanel detections={detections} title="Detections of this process" />

      <dl className="m-0 grid grid-cols-[6rem_minmax(0,1fr)] gap-x-3 gap-y-2 p-4 text-[13px]">
        <Field label="Image" copy={process.image}>
          {process.image}
        </Field>
        <Field label="Command line" copy={process.commandLine}>
          {process.commandLine}
        </Field>
        <Field label="User" copy={process.user}>
          {process.user}
        </Field>
        <Field label="Host">{process.host}</Field>
        <Field label="Started">{Number.isFinite(process.startTs) ? formatDateTime(process.startTs) : ''}</Field>
        <Field label="Ended">{Number.isFinite(process.endTs) ? formatDateTime(process.endTs) : ''}</Field>
        <Field label="Ran">{ran}</Field>
        <Field label="PID">{process.pid}</Field>
        <Field label="Parent PID">{process.ppid}</Field>
        <Field label="GUID" copy={process.guid}>
          {process.guid}
        </Field>
        <Field label="Logon ID">{process.logonId}</Field>
        <Field label="Integrity">{process.integrity}</Field>
        {hashes.map(([name, value]) => (
          <Field key={name} label={name} copy={String(value)}>
            {String(value)}
          </Field>
        ))}
      </dl>

      <section aria-label="Ancestors" className="border-t border-line-soft px-4 py-3">
        <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-fg-muted">Ancestors</h4>
        {!ready && !around.error && <Wait>Reading the tree…</Wait>}
        {around.error && ready && (
          <p role="alert" className="text-xs text-high-fg">
            {around.error}
          </p>
        )}
        {ready && answer && ancestors.length === 0 && !answer.ghost && (
          <p className="m-0 text-xs text-fg-muted">None: it is at the root.</p>
        )}
        {ready && answer && (ancestors.length > 0 || answer.ghost) && (
          <ul className="m-0 list-none space-y-0.5 p-0">
            {answer.ghost && (
              <li
                className="px-1 py-0.5 font-mono text-xs italic text-fg-subtle"
                title={[answer.ghost.image, answer.ghost.commandLine].filter(Boolean).join('\n')}
              >
                {nameOf({ image: answer.ghost.image })} — not in the evidence
              </li>
            )}
            {ancestors.map((ancestor, index) => (
              <Link
                key={ancestor.id}
                process={ancestor}
                onSelect={onSelect}
                indent={(index + (answer.ghost ? 1 : 0)) * 12}
              />
            ))}
          </ul>
        )}
      </section>

      <section aria-label="Children" className="border-t border-line-soft px-4 py-3">
        <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-fg-muted">
          Children <span className="font-mono font-normal normal-case">{process.children || 0}</span>
        </h4>
        {ready && answer && children.length === 0 && <p className="m-0 text-xs text-fg-muted">None.</p>}
        {ready && children.length > 0 && (
          <ul className="m-0 list-none space-y-0.5 p-0">
            {children.slice(0, CHILDREN_SHOWN).map((child) => (
              <Link key={child.id} process={child} onSelect={onSelect} />
            ))}
          </ul>
        )}
        {ready && process.children > CHILDREN_SHOWN && (
          <p className="m-0 mt-1 text-xs text-fg-muted">
            {(process.children - CHILDREN_SHOWN).toLocaleString('en-US')} more: open the process in the tree to page
            through them.
          </p>
        )}
      </section>
    </aside>
  )
}
