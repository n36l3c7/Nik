import { useCallback, useEffect, useState } from 'react'
import { ListChecks, RefreshCw } from 'lucide-react'
import { useAuth } from '../../../context/AuthContext.jsx'
import { useBulk } from '../../../context/BulkContext.jsx'
import { useToast } from '../../../context/ToastContext.jsx'
import { jobLine } from '../../../domain/bulk.js'
import { onBulkEnded } from '../../../lib/bulk.js'
import { formatRelative } from '../../../lib/time.js'
import { api } from '../../../services/api.js'
import { Badge, Button, EmptyState, Wait } from '../../ui/index.js'

/*
 * System → Bulk actions: the actions asked of many incidents, artifacts or
 * indicators at once, the newest first, each with how it went. A row opens
 * "What it did". A person sees their own; an administrator, and who reads the
 * audit log, can see everybody's. Administrators set the limits here: how many
 * rows one action takes, up to how many are done at once, and above how many
 * a closing is confirmed by typing.
 */

const COLORS = { running: 'cyan', done: 'green', cancelled: 'slate', failed: 'red' }
const LIMITS = [
  [
    'maxItems',
    'Rows one action takes at most',
    'More than this is refused: the filter is narrowed and it is done in parts.',
  ],
  ['inlineItems', 'Rows done before the answer', 'A larger action goes on in the background, and survives a restart.'],
  ['typedAbove', 'Closing more than this is typed', 'Deleting is confirmed by typing whatever the number.'],
]
const INPUT =
  'h-9 w-28 border border-line bg-canvas px-3 font-mono text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

function Limits() {
  const { showToast } = useToast()
  const [held, setHeld] = useState(null)
  const [typed, setTyped] = useState({})
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    api
      .get('/bulk/settings')
      .then((found) => (setHeld(found), setTyped(found)))
      .catch((failure) => showToast({ message: failure.message }))
  }, [showToast])
  if (!held) return null
  const changed = LIMITS.some(([key]) => Number(typed[key]) !== held[key])
  const save = async (event) => {
    event.preventDefault()
    setBusy(true)
    try {
      const saved = await api.put(
        '/bulk/settings',
        Object.fromEntries(LIMITS.map(([key]) => [key, Number(typed[key])])),
      )
      setHeld(saved)
      setTyped(saved)
      showToast({ message: 'The limits are saved.' })
    } catch (failure) {
      showToast({ message: failure.message })
    } finally {
      setBusy(false)
    }
  }
  return (
    <form onSubmit={save} aria-label="Limits of the bulk actions" className="space-y-3 border border-line bg-panel p-4">
      <h3 className="font-mono text-xs uppercase tracking-wider text-fg-muted">Limits</h3>
      {LIMITS.map(([key, label, hint]) => (
        <label key={key} className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm" htmlFor={`bulk-${key}`}>
          <input
            id={`bulk-${key}`}
            type="number"
            min="0"
            value={typed[key] ?? ''}
            onChange={(event) => setTyped({ ...typed, [key]: event.target.value })}
            className={INPUT}
          />
          <span className="text-fg">{label}</span>
          <span className="basis-full text-xs text-fg-muted">
            {hint} Default: {held.defaults[key]}.
          </span>
        </label>
      ))}
      <Button type="submit" size="sm" waiting={busy} disabled={!changed || busy}>
        Save the limits
      </Button>
    </form>
  )
}

export default function BulkJobsSection() {
  const { can } = useAuth()
  const { showResult } = useBulk()
  const everybodyAllowed = can('admin') || can('audit.read')
  const [everybody, setEverybody] = useState(false)
  const [jobs, setJobs] = useState(null)
  const [error, setError] = useState(null)

  const load = useCallback(() => {
    api
      .get(`/bulk?everybody=${everybody && everybodyAllowed ? 'true' : 'false'}`)
      .then((found) => (setJobs(found.jobs), setError(null)))
      .catch((failure) => setError(failure.message))
  }, [everybody, everybodyAllowed])
  useEffect(() => {
    load()
    return onBulkEnded(load)
  }, [load])

  return (
    <section className="space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <ListChecks className="h-5 w-5 text-accent" aria-hidden="true" />
          <h2 className="text-base font-semibold text-fg">Bulk actions</h2>
        </div>
        <p className="mt-1 max-w-prose text-sm text-fg-muted">
          What was asked of many incidents, artifacts or indicators at once, and how it went. A job is kept here for a
          month. Each change it made is in the audit log, ending with the first characters of the job.
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="secondary" size="sm" icon={RefreshCw} onClick={load}>
          Refresh
        </Button>
        {everybodyAllowed && (
          <label className="inline-flex items-center gap-2 text-sm text-fg-muted">
            <input
              type="checkbox"
              checked={everybody}
              onChange={(event) => setEverybody(event.target.checked)}
              className="accent-accent"
            />
            Everybody&apos;s, not only mine
          </label>
        )}
      </div>
      {error ? (
        <p role="alert" className="font-mono text-sm text-high">
          {error}
        </p>
      ) : jobs === null ? (
        <Wait>Loading the bulk actions…</Wait>
      ) : jobs.length === 0 ? (
        <EmptyState
          skull
          title="No bulk action yet"
          message="Tick rows of the incidents, the artifacts or the indicators, and choose an action in the bar that appears."
        />
      ) : (
        <ul aria-label="Bulk actions" className="border border-line">
          {jobs.map((job) => (
            <li key={job.id} className="border-b border-line-soft last:border-b-0">
              <button
                type="button"
                onClick={() => showResult(job.id)}
                className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-left text-sm hover:bg-panel focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent"
              >
                <Badge color={COLORS[job.state] ?? 'slate'}>{job.state === 'failed' ? 'given up' : job.state}</Badge>
                <span className="min-w-0 flex-1 basis-64 truncate font-semibold text-fg">{job.label}</span>
                <span className="font-mono text-xs text-fg-muted">{jobLine(job)}</span>
                <span className="font-mono text-xs text-fg-subtle">
                  {job.actor} · {formatRelative(job.createdAt)}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
      {can('admin') && <Limits />}
    </section>
  )
}
