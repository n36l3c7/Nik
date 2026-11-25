import { useState } from 'react'
import { Badge, Button, CopyButton, Modal } from '../ui/index.js'
import LevelBadge from './LevelBadge.jsx'
import { levelsText, reportDetections } from '../../domain/detections.js'
import { sizeText } from '../../domain/transfers.js'
import { formatDateTime } from '../../lib/time.js'
import { canAcknowledge, canReadAgain, canView, noteRows, readPill, reasonRows } from '../../domain/sourceFiles.js'

const number = (n) => (n === null || n === undefined ? '—' : n.toLocaleString('en-US'))
const when = (iso) => (iso ? formatDateTime(Date.parse(iso)) : '')

function Stat({ label, value, hint, tone = '' }) {
  return (
    <div className="flex flex-col gap-1 px-4 py-3">
      <span className="text-xs text-fg-muted">{label}</span>
      <span className={`font-mono text-xl ${tone}`}>{value}</span>
      {hint && <span className="text-xs text-fg-muted">{hint}</span>}
    </div>
  )
}

/**
 * ParseReport: what the worker read of a file, and what it did not. The source is the one of
 * `GET /incidents/{id}/evidence/sources/{sid}` (it carries `report`).
 *
 * `canWrite` shows the actions that change the file (Analyse again, Seen, Remove); `canDownload` is the
 * permission evidence.download. `onView(source)` opens the viewer; `onAgain(source)`,
 * `onSeen(source, note)`, `onForgetSeen(source)`, `onRemove(source)` and `onDownload(source)` do the
 * work and return a promise (a rejection is shown here). `busy` disables the actions meanwhile.
 */
export default function ParseReport({
  source,
  canWrite = false,
  canDownload = false,
  onView = null,
  onDownload = null,
  onAgain = null,
  onSeen = null,
  onForgetSeen = null,
  onRemove = null,
  busy = false,
}) {
  const [dialog, setDialog] = useState(null) // 'seen' | 'remove'
  const [note, setNote] = useState('')
  const [error, setError] = useState('')
  const report = source.report ?? {}
  const reasons = reasonRows(report)
  const notes = noteRows(report)
  const found = reportDetections(report)
  const pill = readPill(source)
  const lostReasons = reasons.length

  const run = async (action) => {
    setError('')
    try {
      await action()
    } catch (failure) {
      setError(failure?.message || 'The change could not be made.')
    }
    setDialog(null)
    setNote('')
  }

  const stopped = source.state === 'done' && report.ended === false
  return (
    <section
      aria-label={`Parse report of ${source.fileName}`}
      className={`border bg-panel ${source.read === 'partial' && !source.seen ? 'border-med-line' : 'border-line'}`}
    >
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-2.5">
        <h3 className="flex min-w-0 items-center gap-2 text-sm font-semibold">
          <span className="truncate">Parse report: {source.fileName}</span>
          <Badge color={pill.color} title={pill.title}>
            {pill.label}
          </Badge>
        </h3>
        <div className="flex flex-wrap gap-2">
          {onView && canView(source) && (
            <Button variant="secondary" size="sm" onClick={() => onView(source)}>
              View source
            </Button>
          )}
          {canDownload && onDownload && canView(source) && (
            <Button variant="secondary" size="sm" disabled={busy} onClick={() => run(() => onDownload(source))}>
              Download original
            </Button>
          )}
          {canWrite && onAgain && canReadAgain(source) && (
            <Button variant="secondary" size="sm" disabled={busy} onClick={() => run(() => onAgain(source))}>
              Analyse again
            </Button>
          )}
          {canWrite && onSeen && canAcknowledge(source) && (
            <Button variant="secondary" size="sm" disabled={busy} onClick={() => setDialog('seen')}>
              Seen
            </Button>
          )}
          {canWrite && onRemove && (
            <Button variant="danger" size="sm" disabled={busy} onClick={() => setDialog('remove')}>
              Remove
            </Button>
          )}
        </div>
      </header>

      {error && (
        <p role="alert" className="border-b border-high-line bg-high-soft px-4 py-2 text-sm text-high-fg">
          {error}
        </p>
      )}

      {source.legacy ? (
        <p className="px-4 py-4 text-sm text-fg-muted">
          This file was imported before 7.0, so there is no report and no original. Import it again to have both.
        </p>
      ) : (
        <>
          <div className="grid grid-cols-2 divide-x divide-line border-b border-line lg:grid-cols-4">
            <Stat
              label="Records in file"
              value={number(source.inFile)}
              hint={source.inFile === null ? 'the file does not say' : ''}
            />
            <Stat
              label="Kept"
              value={number(source.kept)}
              tone="text-accent-fg"
              hint={source.duplicates > 0 ? `${number(source.duplicates)} duplicates not kept` : ''}
            />
            <Stat
              label="Skipped"
              value={number(source.skipped)}
              tone={source.skipped > 0 ? 'text-med-fg' : ''}
              hint={lostReasons > 0 ? `${lostReasons} ${lostReasons === 1 ? 'reason' : 'reasons'}` : ''}
            />
            <Stat label="Original" value={sizeText(source.size)} hint="kept read-only, as long as the artifact" />
          </div>

          {source.error && <p className="border-b border-line px-4 py-3 text-sm text-high-fg">{source.error}</p>}
          {stopped && (
            <p className="border-b border-line px-4 py-3 text-sm text-med-fg">
              The parser stopped before the end of the file.
            </p>
          )}

          {reasons.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full min-w-max text-left text-[13px]">
                <thead className="bg-canvas">
                  <tr className="border-b border-line font-mono text-xs text-fg-muted">
                    <th scope="col" className="px-4 py-2 font-normal">
                      Reason
                    </th>
                    <th scope="col" className="px-4 py-2 text-right font-normal">
                      Records
                    </th>
                    <th scope="col" className="px-4 py-2 font-normal">
                      Where
                    </th>
                    <th scope="col" className="px-4 py-2 font-normal">
                      What happened
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line-soft">
                  {reasons.map((row) => (
                    <tr key={row.reason}>
                      <td className="px-4 py-2">
                        <Badge color="amber">{row.reason}</Badge>
                      </td>
                      <td className="px-4 py-2 text-right font-mono tabular-nums">{number(row.records)}</td>
                      <td className="px-4 py-2 font-mono">{row.where || '—'}</td>
                      <td className="px-4 py-2 text-fg-muted">{row.detail || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {found && (
            <section
              aria-label="Detections of this file"
              className="space-y-2 border-t border-line px-4 py-3 text-[13px]"
            >
              <p className="flex flex-wrap items-baseline gap-2">
                <span className="font-semibold">Detections</span>
                <span className="font-mono tabular-nums">{number(found.total)}</span>
                <span className="text-fg-muted">
                  {found.total > 0 ? levelsText(found.byLevel) : 'No rule matched a record of this file.'}
                </span>
              </p>
              {found.rules.length > 0 && (
                <ul aria-label="The rules that matched most" className="space-y-1">
                  {found.rules.map((rule) => (
                    <li key={rule.id} className="flex flex-wrap items-center gap-2">
                      <LevelBadge level={rule.level} />
                      <span>{rule.title}</span>
                      <span className="font-mono tabular-nums text-fg-muted">{number(rule.count)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          )}

          {notes.length > 0 && (
            <ul aria-label="Notes" className="space-y-1 border-t border-line px-4 py-3 text-[13px]">
              {notes.map((item) => (
                <li key={item.reason} className="flex flex-wrap items-baseline gap-2">
                  <Badge color="cyan">{item.reason}</Badge>
                  <span className="font-mono tabular-nums">{number(item.count)}</span>
                  <span className="text-fg-muted">{item.detail}</span>
                </li>
              ))}
            </ul>
          )}
        </>
      )}

      {source.seen && (
        <div className="flex flex-wrap items-center gap-3 border-t border-line px-4 py-3 text-[13px]">
          <Badge color="slate">seen</Badge>
          <span>
            Seen by {source.seen.by}, {when(source.seen.at)}
            {source.seen.note ? `: ${source.seen.note}` : ''}
          </span>
          {canWrite && onForgetSeen && (
            <Button variant="ghost" size="xs" disabled={busy} onClick={() => run(() => onForgetSeen(source))}>
              Undo
            </Button>
          )}
        </div>
      )}

      <footer className="flex flex-wrap items-center gap-x-6 gap-y-1 border-t border-line px-4 py-3 text-[13px] text-fg-muted">
        {source.parser && (
          <span>
            Parser {source.parser}
            {source.parserVersion ? ` ${source.parserVersion}` : ''}
          </span>
        )}
        {source.parsedAt && <span>Read on the server, {when(source.parsedAt)}</span>}
        {source.sha256 && (
          <span className="inline-flex items-center gap-1 font-mono">
            SHA-256 <span className="break-all">{source.sha256}</span>
            <CopyButton text={source.sha256} label="Copy SHA-256" />
          </span>
        )}
        <span>
          Imported by {source.createdBy || 'unknown'}, {when(source.createdAt)}
        </span>
      </footer>

      <Modal
        open={dialog === 'seen'}
        onClose={() => setDialog(null)}
        title="This file was read in part"
        footer={
          <>
            <Button variant="ghost" onClick={() => setDialog(null)}>
              Cancel
            </Button>
            <Button disabled={busy} onClick={() => run(() => onSeen(source, note.trim()))}>
              Mark as seen
            </Button>
          </>
        }
      >
        <p className="mb-3 text-fg-muted">
          Saying you looked at what was not read takes the warning off the page. The note goes to the audit log and the
          War Room.
        </p>
        <label className="block text-xs text-fg-muted" htmlFor={`seen-note-${source.id}`}>
          Note (optional)
        </label>
        <textarea
          id={`seen-note-${source.id}`}
          value={note}
          maxLength={1000}
          rows={3}
          onChange={(event) => setNote(event.target.value)}
          className="mt-1 w-full border border-line bg-canvas p-2 font-mono text-[13px] text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        />
      </Modal>

      <Modal
        open={dialog === 'remove'}
        onClose={() => setDialog(null)}
        title="Remove this file?"
        footer={
          <>
            <Button variant="ghost" onClick={() => setDialog(null)}>
              Cancel
            </Button>
            <Button variant="danger" disabled={busy} onClick={() => run(() => onRemove(source))}>
              Remove
            </Button>
          </>
        }
      >
        <p>
          <span className="font-mono">{source.fileName}</span> and its records leave the incident. The flags and notes
          on its records stay. The original stays in the store until no incident holds it.
        </p>
      </Modal>
    </section>
  )
}
