import { useCallback, useEffect, useState } from 'react'
import { ChevronDown, ChevronRight, Download, Play, Power, RefreshCw } from 'lucide-react'
import { api } from '../../../services/api.js'
import { setPath } from '../../../lib/location.js'
import { formatDateTime } from '../../../lib/time.js'
import { OUTCOMES, jobText, lastText, limitText, nextText, outcomeBadge, stateBadge } from '../../../domain/fetch.js'
import { Badge, Button } from '../../ui/index.js'

/*
 * Automation → Fetch status (who manages connectors).
 *
 * Every connection whose connector can bring alerts in: whether it does, how
 * it goes (fetching, failing with why, paused with why), when it last
 * fetched and will next, and what its last cycle found. A connection is
 * turned on and off here, made to fetch now, and let go on after a pause.
 * Opened, it lists what it fetched lately with what became of each item:
 * the place to see why an incident came in incomplete.
 */

const REFRESH_MS = 15_000

function Items({ connectionId }) {
  const [items, setItems] = useState(null)
  const [outcome, setOutcome] = useState('')
  useEffect(() => {
    let cancelled = false
    api
      .get(`/fetch/${encodeURIComponent(connectionId)}/items${outcome ? `?outcome=${outcome}` : ''}`)
      .then((found) => !cancelled && setItems(found.items))
      .catch(() => !cancelled && setItems([]))
    return () => {
      cancelled = true
    }
  }, [connectionId, outcome])
  return (
    <div className="flex flex-col gap-2 border-t border-line-soft bg-sunken px-3 py-2">
      <label className="flex items-center gap-2 text-xs text-fg-muted">
        Show
        <select
          aria-label="Which items to show"
          value={outcome}
          onChange={(event) => setOutcome(event.target.value)}
          className="cursor-pointer border border-line bg-canvas px-2 py-1 text-xs text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {OUTCOMES.map((id) => (
            <option key={id} value={id}>
              {id ? outcomeBadge(id).label : 'everything'}
            </option>
          ))}
        </select>
      </label>
      {items === null ? (
        <p role="status" className="font-mono text-xs text-fg-muted">
          Loading…
        </p>
      ) : items.length === 0 ? (
        <p className="text-xs text-fg-muted">Nothing fetched{outcome ? ' with this outcome' : ' yet'}.</p>
      ) : (
        <ul
          aria-label="What it fetched lately"
          className="flex flex-col divide-y divide-line-soft border border-line bg-canvas"
        >
          {items.map((item) => {
            const badge = outcomeBadge(item.outcome)
            return (
              <li key={item.itemId} className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 px-3 py-1.5 text-sm">
                <span className="w-24 shrink-0">
                  <Badge color={badge.color}>{badge.label}</Badge>
                </span>
                <span className="font-mono text-xs text-fg">{item.itemId}</span>
                <span className="text-xs text-fg-muted">{formatDateTime(Date.parse(item.fetchedAt))}</span>
                {item.incidentId && (
                  <button
                    type="button"
                    onClick={() => setPath(`/incident/${encodeURIComponent(item.incidentId)}`)}
                    className="text-xs text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    open the incident
                  </button>
                )}
                {item.note && <span className="basis-full text-xs text-fg-muted">{item.note}</span>}
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}

export default function FetchStatusSection() {
  const [connections, setConnections] = useState(null)
  const [jobs, setJobs] = useState([])
  const [error, setError] = useState(null)
  const [said, setSaid] = useState(null)
  const [open, setOpen] = useState(null)
  const [busy, setBusy] = useState(null)

  const load = useCallback(async () => {
    try {
      const [status, waiting] = await Promise.all([api.get('/fetch'), api.get('/mirror/queue')])
      setConnections(status.connections)
      setJobs(waiting.jobs)
      setError(null)
    } catch (failure) {
      setError(failure.message)
    }
  }, [])
  useEffect(() => {
    load()
    const timer = setInterval(() => document.visibilityState === 'visible' && load(), REFRESH_MS)
    return () => clearInterval(timer)
  }, [load])

  const act = async (connection, request, done) => {
    setBusy(connection.connectionId)
    setError(null)
    setSaid(null)
    try {
      const answer = await request()
      setSaid(typeof done === 'function' ? done(answer) : done)
      await load()
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(null)
    }
  }
  const path = (connection) => `/fetch/${encodeURIComponent(connection.connectionId)}`

  return (
    <div className="flex max-w-5xl flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <p className="max-w-3xl text-sm text-fg-muted">
          The connections that can bring alerts in as incidents. One that is on is read by the automation worker at its
          interval; an alert it has seen before is skipped. How an alert becomes an incident is said in{' '}
          <em>Classifiers and mappers</em>.
        </p>
        <Button variant="secondary" size="sm" icon={RefreshCw} onClick={load}>
          Refresh
        </Button>
      </div>
      {(error || said) && (
        <p role={error ? 'alert' : 'status'} className={`text-sm ${error ? 'text-high-fg' : 'text-fg-muted'}`}>
          {error || said}
        </p>
      )}
      {connections === null && !error ? (
        <p role="status" className="font-mono text-sm text-fg-muted">
          Loading…
        </p>
      ) : connections?.length === 0 ? (
        <p className="text-sm text-fg-muted">
          No connection can fetch: none of its connectors says how (the key <code className="font-mono">fetch</code> of
          a connector file).
        </p>
      ) : (
        <ul aria-label="Instances that can fetch" className="flex flex-col border border-line">
          {(connections ?? []).map((connection) => {
            const badge = stateBadge(connection)
            const expanded = open === connection.connectionId
            const working = busy === connection.connectionId
            const last = lastText(connection)
            const near = limitText(connection)
            return (
              <li key={connection.connectionId} className="border-b border-line-soft last:border-b-0">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-2 px-3 py-2.5">
                  <button
                    type="button"
                    aria-expanded={expanded}
                    aria-label={`${expanded ? 'Hide' : 'Show'} what ${connection.connection} fetched`}
                    onClick={() => setOpen(expanded ? null : connection.connectionId)}
                    className="p-1 text-fg-muted hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                  </button>
                  <span className="min-w-0 flex-1">
                    <span className="flex flex-wrap items-center gap-2 text-sm font-medium text-fg">
                      {connection.connection}
                      <Badge color={badge.color}>{badge.label}</Badge>
                      <span className="text-xs font-normal text-fg-muted">{connection.connector}</span>
                    </span>
                    <span className="block text-xs text-fg-muted">
                      {connection.state === 'off'
                        ? 'It does not fetch.'
                        : [
                            connection.lastAt
                              ? `last ${formatDateTime(Date.parse(connection.lastAt))}`
                              : 'not yet fetched',
                            last,
                            `next ${nextText(connection)}`,
                            near,
                          ]
                            .filter(Boolean)
                            .join(' · ')}
                    </span>
                    {connection.error && <span className="block text-xs text-high-fg">{connection.error}</span>}
                    {connection.pausedWhy && <span className="block text-xs text-med-fg">{connection.pausedWhy}</span>}
                    {connection.truncated && (
                      <span className="block text-xs text-fg-muted">
                        The last cycle stopped at its limit: the rest comes with the next.
                      </span>
                    )}
                  </span>
                  <span className="flex shrink-0 flex-wrap gap-2">
                    {connection.enabled && connection.state !== 'ok' && (
                      <Button
                        size="sm"
                        disabled={working}
                        onClick={() =>
                          act(
                            connection,
                            () => api.post(`${path(connection)}/resume`),
                            `${connection.connection} goes on.`,
                          )
                        }
                      >
                        Let it go on
                      </Button>
                    )}
                    {connection.enabled && (
                      <Button
                        variant="secondary"
                        size="sm"
                        icon={Download}
                        disabled={working}
                        onClick={() =>
                          act(
                            connection,
                            () => api.post(`${path(connection)}/run`),
                            (answer) =>
                              answer.result.state === 'failing'
                                ? `${connection.connection}: ${answer.result.error}`
                                : `${connection.connection}: ${answer.result.fetched} read, ${answer.result.new} new.`,
                          )
                        }
                      >
                        Fetch now
                      </Button>
                    )}
                    <Button
                      variant={connection.enabled ? 'ghost' : 'primary'}
                      size="sm"
                      icon={connection.enabled ? Power : Play}
                      disabled={working}
                      onClick={() =>
                        act(
                          connection,
                          () => api.put(path(connection), { enabled: !connection.enabled }),
                          connection.enabled
                            ? `${connection.connection} does not fetch any more.`
                            : `${connection.connection} fetches: its first cycle is at the next turn of the worker.`,
                        )
                      }
                    >
                      {connection.enabled ? 'Turn off' : 'Turn on'}
                    </Button>
                  </span>
                </div>
                {expanded && <Items connectionId={connection.connectionId} />}
              </li>
            )
          })}
        </ul>
      )}

      <section aria-label="Mirroring: what waits to be sent" className="flex flex-col gap-2">
        <h3 className="text-sm font-semibold text-fg">Mirroring: what waits to be sent</h3>
        {jobs.length === 0 ? (
          <p className="text-sm text-fg-muted">
            Nothing waits. What changes in an incident mirrored out is sent by the worker; what it could not send is
            listed here with why.
          </p>
        ) : (
          <ul className="flex flex-col divide-y divide-line-soft border border-line">
            {jobs.map((job) => (
              <li key={job.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm">
                <Badge color={job.status === 'failed' ? 'red' : job.attempts ? 'amber' : 'slate'}>
                  {job.status === 'failed' ? 'not sent' : 'waiting'}
                </Badge>
                <span className="min-w-0 flex-1">
                  <button
                    type="button"
                    onClick={() => setPath(`/incident/${encodeURIComponent(job.incidentId)}`)}
                    className="text-left text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    {job.incident || job.incidentId}
                  </button>
                  <span className="block text-xs text-fg-muted">
                    to {job.connection} · {jobText(job)}
                  </span>
                  {job.error && <span className="block text-xs text-high-fg">{job.error}</span>}
                </span>
                <Button
                  variant="secondary"
                  size="xs"
                  onClick={async () => {
                    setError(null)
                    try {
                      setJobs((await api.post(`/mirror/queue/${encodeURIComponent(job.id)}/retry`)).jobs)
                    } catch (failure) {
                      setError(failure.message)
                    }
                  }}
                >
                  Send again
                </Button>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}
