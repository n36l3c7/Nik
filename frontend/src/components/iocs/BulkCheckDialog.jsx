import { useEffect, useState } from 'react'
import { api } from '../../services/api.js'
import { durationLabel, sourceLine } from '../../domain/iocLibrary.js'
import { Button, Modal, StatCard } from '../ui/index.js'

/*
 * Bulk check: before anything is asked, what it costs against each source's
 * quota. The check then runs in the background; what does not fit today waits
 * for the quota and goes on by itself.
 */

/**
 * @param {{ request: { scope: object, label: string } | null, onClose: () => void, onStarted: () => void }} props
 */
export default function BulkCheckDialog({ request, onClose, onStarted }) {
  const [force, setForce] = useState(false)
  const [plan, setPlan] = useState(null)
  const [label, setLabel] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (request) setForce(false)
  }, [request])

  useEffect(() => {
    if (!request) return undefined
    let cancelled = false
    setPlan(null)
    setError(null)
    api
      .post('/iocs/check', { scope: request.scope, force, dryRun: true })
      .then((result) => !cancelled && (setPlan(result.plan), setLabel(result.label)))
      .catch((err) => !cancelled && setError(err.message))
    return () => {
      cancelled = true
    }
  }, [request, force])

  if (!request) return null
  const start = async () => {
    setBusy(true)
    setError(null)
    try {
      await api.post('/iocs/check', { scope: request.scope, force })
      onStarted()
      onClose()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }
  const later = plan?.sources.some((source) => source.later > 0)

  return (
    <Modal
      open
      onClose={onClose}
      title={`Check ${plan ? plan.total : '…'} indicators · ${request.label || label}`}
      maxWidth="max-w-2xl"
      footer={
        <div className="flex w-full flex-wrap items-center justify-between gap-2">
          <span className="text-xs text-fg-muted">It runs in the background: a notice appears when it is done.</span>
          <span className="flex gap-2">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button disabled={busy || !plan || plan.toAsk === 0} onClick={start}>
              {busy ? 'Starting…' : 'Start'}
            </Button>
          </span>
        </div>
      }
    >
      {!plan ? (
        <p role={error ? 'alert' : 'status'} className={`text-sm ${error ? 'font-mono text-high' : 'text-fg-muted'}`}>
          {error ?? 'Counting…'}
        </p>
      ) : (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <StatCard label="To ask" value={plan.toAsk} />
            <StatCard label="Still fresh, reused" value={plan.reused} />
            <StatCard label="Never sent out" value={plan.neverSent} />
            <StatCard label="Takes about" value={durationLabel(plan.seconds)} />
          </div>
          {plan.sources.length === 0 ? (
            <p className="text-sm text-fg-muted">
              {plan.toAsk === 0 && plan.reused > 0
                ? 'Every answer is still fresh: nothing to ask. Tick "Ask everything again" to ask anyway.'
                : 'No source can be asked about these indicators: enable one in Settings → Threat intelligence.'}
            </p>
          ) : (
            <section className="space-y-1.5" aria-label="Per source">
              <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">Per source</h3>
              <ul>
                {plan.sources.map((source) => {
                  const share = source.needed ? Math.round((source.today / source.needed) * 100) : 100
                  return (
                    <li
                      key={source.provider}
                      className="grid grid-cols-[10rem_minmax(0,1fr)] items-center gap-x-3 gap-y-1 border-b border-line-soft py-1.5 text-sm sm:grid-cols-[10rem_minmax(0,1fr)_auto]"
                    >
                      <span>
                        {source.label}{' '}
                        {source.keys > 0 && (
                          <span className="text-xs text-fg-subtle">
                            {source.keys} {source.keys === 1 ? 'key' : 'keys'}
                          </span>
                        )}
                      </span>
                      <span className="flex h-2 bg-line-soft" aria-hidden="true">
                        <i
                          className={`block h-full ${source.later > 0 ? 'bg-med-line' : 'bg-accent'}`}
                          style={{ width: `${share}%` }}
                        />
                      </span>
                      <span
                        className={`col-span-2 font-mono text-xs sm:col-span-1 ${source.later > 0 ? 'text-med' : 'text-fg-muted'}`}
                      >
                        {sourceLine(source)}
                      </span>
                    </li>
                  )
                })}
              </ul>
            </section>
          )}
          {later && (
            <p className="border-l-2 border-med-line bg-med-soft/50 px-3 py-2 text-sm">
              Today&apos;s quota does not cover everything. Nik asks what it can, tells you when it has to wait, and
              goes on by itself when the quota resets.
            </p>
          )}
          <div className="flex flex-wrap gap-x-5 gap-y-1 text-sm">
            <label className="flex items-center gap-2">
              <input type="radio" name="ioc-check-scope" checked={!force} onChange={() => setForce(false)} />
              Only missing or expired answers
            </label>
            <label className="flex items-center gap-2">
              <input type="radio" name="ioc-check-scope" checked={force} onChange={() => setForce(true)} />
              Ask everything again
            </label>
          </div>
          {error && (
            <p role="alert" className="font-mono text-xs text-high">
              {error}
            </p>
          )}
        </div>
      )}
    </Modal>
  )
}
