import { useCallback, useEffect, useState } from 'react'
import { api } from '../../../services/api.js'
import { setPath } from '../../../lib/location.js'
import { jobText } from '../../../domain/fetch.js'
import { Badge, Button } from '../../ui/index.js'

/*
 * Mirroring: what waits to be sent, under the connectors.
 *
 * What changes in an incident mirrored out is sent by the worker; what it
 * could not send yet, or gave up on, is listed here with why, and can be sent
 * again. Nothing is shown while nothing waits.
 */

const REFRESH_MS = 15_000

export default function MirrorQueue() {
  const [jobs, setJobs] = useState([])
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    try {
      setJobs((await api.get('/mirror/queue')).jobs)
    } catch {
      // What is shown stays until the next turn.
    }
  }, [])
  useEffect(() => {
    load()
    const timer = setInterval(() => document.visibilityState === 'visible' && load(), REFRESH_MS)
    return () => clearInterval(timer)
  }, [load])

  if (jobs.length === 0) return null
  return (
    <section aria-label="Mirroring: what waits to be sent" className="flex max-w-5xl flex-col gap-2">
      <h3 className="text-sm font-semibold text-fg">Mirroring: what waits to be sent</h3>
      {error && (
        <p role="alert" className="text-sm text-high-fg">
          {error}
        </p>
      )}
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
    </section>
  )
}
