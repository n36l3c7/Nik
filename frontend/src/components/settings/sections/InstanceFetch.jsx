import { useCallback, useEffect, useState } from 'react'
import { Download, ListChecks, RotateCcw } from 'lucide-react'
import { api } from '../../../services/api.js'
import { setPath } from '../../../lib/location.js'
import { formatDateTime } from '../../../lib/time.js'
import {
  OUTCOMES,
  intervalText,
  lastText,
  limitText,
  lookbackHint,
  nextText,
  outcomeBadge,
  resetText,
  stateBadge,
} from '../../../domain/fetch.js'
import { Badge, Button, Modal } from '../../ui/index.js'
import Switch from './Switch.jsx'

/*
 * Fetching, in the form of an instance whose connector can bring alerts in.
 *
 * What is set: whether the instance fetches, how often, how far back the
 * first cycle reads, and the look-back. These belong to the form of the
 * instance (InstancePane.jsx), which holds them and saves them with
 * everything else: there is one "Save".
 *
 * What is done at once, and is not part of the save: fetching now, letting a
 * paused or failing instance go on, resetting the last run, and looking at
 * what it fetched lately with what became of each item.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 font-mono text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-60'
const REFRESH_MS = 15_000

/** What the instance fetched lately, with what became of each item, and the last item as it came. */
function Fetched({ instance }) {
  const [items, setItems] = useState(null)
  const [outcome, setOutcome] = useState('')
  const [sample, setSample] = useState(undefined)
  const path = `/fetch/${encodeURIComponent(instance.id)}`
  useEffect(() => {
    let cancelled = false
    api
      .get(`${path}/items${outcome ? `?outcome=${outcome}` : ''}`)
      .then((found) => !cancelled && setItems(found.items))
      .catch(() => !cancelled && setItems([]))
    return () => {
      cancelled = true
    }
  }, [path, outcome])
  useEffect(() => {
    let cancelled = false
    api
      .get(`${path}/sample`)
      .then((found) => !cancelled && setSample(found.item ?? null))
      .catch(() => !cancelled && setSample(null))
    return () => {
      cancelled = true
    }
  }, [path])
  return (
    <div className="flex flex-col gap-3 text-sm">
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
          className="flex max-h-[45vh] flex-col divide-y divide-line-soft overflow-y-auto border border-line bg-canvas"
        >
          {items.map((item) => {
            const badge = outcomeBadge(item.outcome)
            return (
              <li key={item.itemId} className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 px-3 py-1.5 text-sm">
                <span className="w-24 shrink-0">
                  <Badge color={badge.color}>{badge.label}</Badge>
                </span>
                <span className="break-all font-mono text-xs text-fg">{item.itemId}</span>
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
      {sample && (
        <details>
          <summary className="cursor-pointer text-sm text-link focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent">
            The last item, as it came
          </summary>
          <pre
            aria-label="The last item, as it came"
            className="mt-2 max-h-60 overflow-auto border border-line bg-sunken p-3 font-mono text-xs leading-relaxed text-fg"
          >
            {JSON.stringify(sample, null, 2)}
          </pre>
        </details>
      )}
    </div>
  )
}

/**
 * @param {{
 *   connector: object,
 *   instance: object | null,            // null: an instance that is being made (nothing to show or do yet)
 *   form: { enabled: boolean, interval: string, firstFetch: string, lookback: string },
 *   onForm: (form: object) => void,
 *   status: object | null,              // how it goes, as GET /api/fetch says of the instance
 *   onStatus: (status: object) => void,
 * }} props
 */
export default function InstanceFetch({ connector, instance, form, onForm, status, onStatus }) {
  const [busy, setBusy] = useState('')
  const [error, setError] = useState(null)
  const [said, setSaid] = useState('')
  const [resetting, setResetting] = useState(false)
  const [looking, setLooking] = useState(false)
  const theirs = connector.fetch ?? {}
  const byTime = theirs.byTime !== false
  const minInterval = status?.minIntervalSeconds ?? 30
  const path = instance ? `/fetch/${encodeURIComponent(instance.id)}` : null
  const instanceId = instance?.id ?? null

  // How it goes changes by itself: the worker fetches while the form is open.
  const refresh = useCallback(async () => {
    if (!instanceId) return
    try {
      const found = await api.get('/fetch')
      const mine = found.instances.find((item) => item.instanceId === instanceId)
      if (mine) onStatus(mine)
    } catch {
      // What is shown stays until the next turn.
    }
  }, [instanceId, onStatus])
  useEffect(() => {
    const timer = setInterval(() => document.visibilityState === 'visible' && refresh(), REFRESH_MS)
    return () => clearInterval(timer)
  }, [refresh])

  const run = (name, work, done) => {
    setBusy(name)
    setError(null)
    setSaid('')
    work()
      .then(done, (failure) => setError(failure.message))
      .finally(() => setBusy(''))
  }
  const fetchNow = () =>
    run(
      'run',
      () => api.post(`${path}/run`),
      (answer) => {
        onStatus(answer.status)
        setSaid(
          answer.result.state === 'failing'
            ? answer.result.error
            : `${answer.result.fetched} read, ${answer.result.new} new.`,
        )
      },
    )
  const resume = () =>
    run(
      'resume',
      () => api.post(`${path}/resume`),
      (answer) => {
        onStatus(answer)
        setSaid(`${instance.name} goes on.`)
      },
    )
  const reset = () =>
    run(
      'reset',
      () => api.post(`${path}/reset`),
      (answer) => {
        onStatus(answer)
        setResetting(false)
        setSaid(`The last run of ${instance.name} was reset: its next cycle starts from the first fetch.`)
      },
    )

  const set = (patch) => onForm({ ...form, ...patch })
  const badge = stateBadge(status)
  const on = Boolean(status?.enabled)
  const last = lastText(status)
  const near = limitText(status)

  return (
    <section aria-label="Fetch" className="flex flex-col gap-3 text-sm">
      <div className="flex items-center gap-3">
        <Switch checked={form.enabled} label="Fetch incidents" onChange={(enabled) => set({ enabled })} />
        <span className="text-fg">Fetch incidents</span>
      </div>
      <p className="text-xs text-fg-muted">
        When it is on, the automation worker reads {connector.name} again and again, and each alert it has not seen
        becomes an incident, of the type the classifier gives and with the fields the mapper gives.
      </p>

      <label className="flex flex-col gap-1 text-fg-muted" htmlFor="fetch-interval">
        How often (seconds)
        <input
          id="fetch-interval"
          type="number"
          min={minInterval}
          max={86400}
          value={form.interval}
          onChange={(event) => set({ interval: event.target.value })}
          className={INPUT}
        />
        <span className="text-xs">
          {[
            intervalText(form.interval) && `Every ${intervalText(form.interval)}.`,
            `The connector says ${theirs.intervalSeconds ?? 120}; ${minInterval} at the least.`,
          ]
            .filter(Boolean)
            .join(' ')}
        </span>
      </label>

      <label className="flex flex-col gap-1 text-fg-muted" htmlFor="fetch-first">
        First fetch
        <input
          id="fetch-first"
          type="text"
          value={form.firstFetch}
          maxLength={40}
          spellCheck={false}
          autoComplete="off"
          placeholder={theirs.firstFetch ?? '3 days'}
          onChange={(event) => set({ firstFetch: event.target.value })}
          className={INPUT}
        />
        <span className="text-xs">
          How far back the first cycle reads: 30 minutes, 12 hours, 3 days. Changed later, it counts from the next time
          the last run is reset.
        </span>
      </label>

      <label className="flex flex-col gap-1 text-fg-muted" htmlFor="fetch-lookback">
        Look-back (minutes)
        <input
          id="fetch-lookback"
          type="number"
          min={0}
          max={status?.maxLookbackMinutes ?? 1440}
          value={byTime ? form.lookback : ''}
          disabled={!byTime}
          onChange={(event) => set({ lookback: event.target.value })}
          className={INPUT}
        />
        <span className="text-xs">{lookbackHint(form, { byTime })}</span>
      </label>

      {!instance ? (
        <p className="text-xs text-fg-muted">
          How it goes is shown here once the instance is made, with what it fetched.
        </p>
      ) : (
        <div aria-label="How it goes" role="group" className="flex flex-col gap-2 border-t border-line-soft pt-3">
          <p className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">How it goes</span>
            <Badge color={badge.color}>{badge.label}</Badge>
          </p>
          <p className="text-xs text-fg-muted">
            {!on
              ? 'It does not fetch.'
              : [
                  status.lastAt ? `last ${formatDateTime(Date.parse(status.lastAt))}` : 'not yet fetched',
                  last,
                  `next ${nextText(status)}`,
                  near,
                ]
                  .filter(Boolean)
                  .join(' · ')}
          </p>
          {on && status.sinceAt && (
            <p className="text-xs text-fg-muted">
              The next cycle asks from {formatDateTime(Date.parse(status.sinceAt))}
              {status.started ? '' : ': the first fetch'}.
            </p>
          )}
          {status?.error && <p className="text-xs text-high-fg">{status.error}</p>}
          {status?.pausedWhy && <p className="text-xs text-med-fg">{status.pausedWhy}</p>}
          {status?.truncated && (
            <p className="text-xs text-fg-muted">The last cycle stopped at its limit: the rest comes with the next.</p>
          )}
          {form.enabled !== on && (
            <p className="text-xs text-med-fg">
              {form.enabled
                ? 'It fetches once the instance is saved.'
                : 'It stops fetching once the instance is saved.'}
            </p>
          )}
          <div className="flex flex-wrap gap-2">
            <Button
              waiting={busy === 'run'}
              variant="secondary"
              size="sm"
              icon={Download}
              disabled={!on || busy !== ''}
              title={on ? undefined : 'It does not fetch: turn fetching on and save first'}
              onClick={fetchNow}
            >
              {busy === 'run' ? 'Fetching…' : 'Fetch now'}
            </Button>
            {on && status.state !== 'ok' && (
              <Button size="sm" disabled={busy !== ''} onClick={resume}>
                Resume
              </Button>
            )}
            <Button
              variant="secondary"
              size="sm"
              icon={RotateCcw}
              disabled={busy !== ''}
              onClick={() => setResetting(true)}
            >
              Reset last run…
            </Button>
            <Button variant="secondary" size="sm" icon={ListChecks} onClick={() => setLooking(true)}>
              What it fetched…
            </Button>
          </div>
          {(error || said) && (
            <p role={error ? 'alert' : 'status'} className={`text-xs ${error ? 'text-high-fg' : 'text-fg-muted'}`}>
              {error || said}
            </p>
          )}
        </div>
      )}

      <Modal
        open={resetting}
        onClose={() => setResetting(false)}
        title="Reset the last run?"
        footer={
          <>
            <Button variant="secondary" onClick={() => setResetting(false)}>
              Cancel
            </Button>
            <Button variant="danger" disabled={busy !== ''} onClick={reset}>
              Reset last run
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg">
          <span className="font-semibold">{instance?.name}</span> forgets where its last run stopped.{' '}
          {resetText(status)}
        </p>
      </Modal>

      <Modal
        open={looking}
        onClose={() => setLooking(false)}
        title={instance ? `What ${instance.name} fetched` : ''}
        maxWidth="max-w-3xl"
        footer={<Button onClick={() => setLooking(false)}>Close</Button>}
      >
        {looking && instance && <Fetched instance={instance} />}
      </Modal>
    </section>
  )
}
