import { useCallback, useEffect, useState } from 'react'
import { RefreshCw, ServerCog } from 'lucide-react'
import { api } from '../../../services/api.js'
import { formatRelative } from '../../../lib/time.js'
import { notAnswering, workerName, workerStatus } from '../../../domain/workers.js'
import { Badge, Button } from '../../ui/index.js'

/*
 * System → Workers (admins): the automation worker and the analysis workers,
 * and whether each one answers. The server checks them by itself and tells
 * every administrator when one goes down and when it is back; this page is
 * where those notices lead.
 */

export default function WorkersSection() {
  const [found, setFound] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      // With the moment it was read: "for 12 minutes" is counted from it.
      setFound({ ...(await api.get('/workers')), readAt: Date.now() })
      setError(null)
    } catch (failure) {
      setError(failure.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const now = found?.readAt ?? 0
  const workers = found?.workers ?? []
  const silent = notAnswering(workers)
  const minutes = Math.round((found?.downAfterSeconds ?? 120) / 60)

  return (
    <section className="space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <ServerCog className="h-5 w-5 text-accent" aria-hidden="true" />
          <h2 className="text-base font-semibold text-fg">Workers</h2>
        </div>
        <p className="mt-1 max-w-prose text-sm text-fg-muted">
          The processes Nik hands work to. The server asks each one that is configured every half minute. When one has
          not answered for {minutes} minutes every administrator is told, and told again when it is back.
        </p>
      </div>

      {error && (
        <p role="alert" className="max-w-xl border border-high-line bg-high-soft px-3 py-2 text-sm text-high">
          {error}
        </p>
      )}
      {!found && !error && (
        <p role="status" className="font-mono text-sm text-fg-muted">
          Loading…
        </p>
      )}

      {found && (
        <div className="max-w-2xl space-y-3">
          <div className="flex items-center justify-between gap-3">
            <p role="status" className="text-sm text-fg-muted">
              {silent === 0
                ? 'Every configured worker answers.'
                : `${silent} ${silent === 1 ? 'worker does' : 'workers do'} not answer.`}{' '}
              {found.checkedAt ? `Checked ${formatRelative(found.checkedAt)}.` : 'Not checked yet.'}
            </p>
            <Button variant="secondary" size="sm" icon={RefreshCw} disabled={loading} onClick={load}>
              Refresh
            </Button>
          </div>
          <ul aria-label="Workers" className="divide-y divide-line border border-line bg-panel">
            {workers.map((worker) => {
              const status = workerStatus(worker, now)
              return (
                <li key={worker.id} className="flex items-start justify-between gap-3 px-3 py-2">
                  <div className="min-w-0">
                    <p className="text-sm text-fg">{workerName(worker)}</p>
                    {status.detail && <p className="mt-0.5 text-xs text-fg-muted">{status.detail}</p>}
                  </div>
                  <Badge color={status.color}>{status.text}</Badge>
                </li>
              )
            })}
          </ul>
          <p className="max-w-prose text-xs text-fg-muted">
            A worker that does not answer is a container that is stopped or cannot be reached: look at it with your
            container tool. One that is not configured has no address in the server’s configuration.
          </p>
        </div>
      )}
    </section>
  )
}
