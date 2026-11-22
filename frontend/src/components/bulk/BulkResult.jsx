import { useCallback, useEffect, useState } from 'react'
import { Download, RotateCcw, Square } from 'lucide-react'
import { useToast } from '../../context/ToastContext.jsx'
import { jobEnded, jobLine, notable, retryCount } from '../../domain/bulk.js'
import { workLine } from '../../domain/restarts.js'
import { cancelBulk, retryBulk } from '../../lib/bulk.js'
import { formatRelative } from '../../lib/time.js'
import { api, apiUrl } from '../../services/api.js'
import { Badge, Button, Modal, Wait } from '../ui/index.js'

/*
 * "What it did": the result of a bulk job. How it went in a line, then the
 * items that were not done, each with the sentence that says why: refused
 * and failed first, then what was skipped. Everything, item by item, is the
 * CSV. A job that is still running can be stopped from here; one that ended
 * with items failed or not reached can be tried again on those.
 */

const COLORS = { failed: 'red', refused: 'amber', skipped: 'slate', pending: 'slate', done: 'green' }
const WORDS = { failed: 'failed', refused: 'refused', skipped: 'skipped', pending: 'not done', done: 'done' }
const SHOWN = 200

/**
 * @param {{
 *   job: object | string,                 // a job, or the id of one
 *   onClose: () => void,
 *   onResult: (job: object) => void,      // show another job (the one "Try again" made)
 * }} props
 */
export default function BulkResult({ job: given, onClose, onResult }) {
  const { showToast } = useToast()
  const id = typeof given === 'string' ? given : given.id
  const [job, setJob] = useState(typeof given === 'string' ? null : given)
  const [items, setItems] = useState(given?.items ? notable(given.items) : null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try {
      const found = await api.get(`/bulk/${id}`, { background: true })
      setJob(found)
      // What was not done, the gravest first: three short readings, not every item of a large job.
      const parts = await Promise.all(
        ['failed', 'refused', 'pending', 'skipped'].map((state) =>
          found[state] > 0
            ? api.get(`/bulk/${id}/items?state=${state}&limit=${SHOWN}`, { background: true })
            : { items: [] },
        ),
      )
      setItems(parts.flatMap((part) => part.items))
      setError(null)
      return found
    } catch (failure) {
      setError(failure.message)
      return null
    }
  }, [id])

  useEffect(() => {
    let alive = true
    let timer = null
    const turn = async () => {
      const found = await load()
      if (alive && found && !jobEnded(found)) timer = setTimeout(turn, 1500)
    }
    turn()
    return () => {
      alive = false
      clearTimeout(timer)
    }
  }, [load])

  const again = async () => {
    setBusy(true)
    try {
      const made = await retryBulk(id, { onStarted: (started) => onResult(started) })
      onResult(made)
    } catch (failure) {
      showToast({ message: failure.message })
      setBusy(false)
    }
  }
  const stop = async () => {
    try {
      setJob(await cancelBulk(id))
    } catch (failure) {
      showToast({ message: failure.message })
    }
  }

  const left = job ? retryCount(job) : 0
  const cut = job?.work ? workLine(job.work) : ''
  const hidden = job && items ? job.failed + job.refused + job.skipped + job.pending - items.length : 0
  return (
    <Modal
      open
      onClose={onClose}
      title="What it did"
      maxWidth="max-w-2xl"
      footer={
        <>
          {job && (
            <a
              href={apiUrl(`/bulk/${id}/result.csv`)}
              className="mr-auto inline-flex h-9 items-center gap-2 border border-line px-4 text-sm text-fg hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <Download className="h-4 w-4" aria-hidden="true" />
              Download the result (CSV)
            </a>
          )}
          {job?.state === 'running' && !job.cancelling && (
            <Button variant="secondary" icon={Square} onClick={stop}>
              Stop it
            </Button>
          )}
          {left > 0 && (
            <Button variant="secondary" icon={RotateCcw} waiting={busy} disabled={busy} onClick={again}>
              Try again on the {left} not done
            </Button>
          )}
          <Button onClick={onClose}>Close</Button>
        </>
      }
    >
      <div className="flex flex-col gap-3 text-sm">
        {!job && !error && <Wait>Loading the result…</Wait>}
        {error && (
          <p role="alert" className="text-high-fg">
            {error}
          </p>
        )}
        {job && (
          <>
            <p className="font-semibold text-fg">{job.label}</p>
            <p role="status" aria-label="Result of the bulk action" className="font-mono text-xs text-fg">
              {jobLine(job)}
            </p>
            <p className="text-xs text-fg-muted">
              Asked by {job.actor} {formatRelative(job.createdAt)}
              {job.selection?.query ? ' · everything a filter kept' : ''}
              {job.retryOf ? ' · a second try of an earlier job' : ''}
            </p>
            {job.note && <p className="border border-med-line bg-med-soft px-3 py-2 text-med-fg">{job.note}</p>}
            {cut && <p className="text-xs text-fg-muted">{cut}</p>}
            {items === null ? (
              <Wait>Loading what was not done…</Wait>
            ) : items.length === 0 ? (
              job.state !== 'running' && <p className="text-fg-muted">Everything it was asked was done.</p>
            ) : (
              <div className="max-h-80 overflow-auto border border-line">
                <table aria-label="Items not done" className="w-full border-collapse text-left text-xs">
                  <thead className="sticky top-0 bg-panel font-mono text-fg-muted">
                    <tr>
                      <th scope="col" className="px-2 py-1.5 font-normal">
                        Item
                      </th>
                      <th scope="col" className="px-2 py-1.5 font-normal">
                        Result
                      </th>
                      <th scope="col" className="px-2 py-1.5 font-normal">
                        Why
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((item) => (
                      <tr key={item.ref} className="border-t border-line-soft align-top">
                        <td className="max-w-[16rem] break-all px-2 py-1.5 font-mono">{item.name || item.ref}</td>
                        <td className="px-2 py-1.5">
                          <Badge color={COLORS[item.state]}>{WORDS[item.state]}</Badge>
                        </td>
                        <td className="px-2 py-1.5 text-fg-muted">{item.note}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {hidden > 0 && <p className="text-xs text-fg-muted">{hidden} more are in the CSV.</p>}
          </>
        )}
      </div>
    </Modal>
  )
}
