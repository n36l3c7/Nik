import { useCallback, useEffect, useState } from 'react'
import { ArrowLeftRight, Download, ListChecks, RotateCcw } from 'lucide-react'
import { api } from '../../../services/api.js'
import { useAuth } from '../../../context/AuthContext.jsx'
import { setPath } from '../../../lib/location.js'
import { formatDateTime } from '../../../lib/time.js'
import {
  OUTCOMES,
  appliedText,
  applyText,
  choiceLabel,
  intervalText,
  mirrorChoices,
  sends,
  lastText,
  limitText,
  lookbackHint,
  nextText,
  outcomeBadge,
  resetText,
  stateBadge,
} from '../../../domain/fetch.js'
import { Badge, Button, Modal, Wait } from '../../ui/index.js'
import FindIndicatorsSwitch from './FindIndicatorsSwitch.jsx'
import Switch from './Switch.jsx'

/*
 * Fetching, in the form of an instance whose connector can bring alerts in.
 *
 * What is set: whether the instance fetches, how often, how far back the
 * first cycle reads, the look-back, and the direction the incidents it makes
 * are mirrored in (None, In, Out, In-out, with the classes of data a mirror
 * that sends may carry). These belong to the form of the
 * instance (InstancePane.jsx), which holds them and saves them with
 * everything else: there is one "Save".
 *
 * What is done at once, and is not part of the save: fetching now, letting a
 * paused or failing instance go on, resetting the last run, looking at what
 * it fetched lately with what became of each item, giving the saved
 * direction to the open incidents fetched before (the choice itself is for
 * those fetched from then on), and whether the incidents of this instance are
 * read for indicators (FindIndicatorsSwitch.jsx: it is kept with the setting
 * of Settings, Indicators found, not with the instance, and says so).
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
        <Wait>Reading what it fetched…</Wait>
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
  // Giving the saved direction to what was fetched before: how many they are, asked when the dialog opens.
  const [applying, setApplying] = useState(null)
  const theirs = connector.fetch ?? {}
  const { can } = useAuth()
  const saved = status?.mirror?.direction ?? 'none'
  // A direction that sends is for who may run playbooks; the others see why it is not offered.
  const choices = mirrorChoices(connector, { canSend: can('automation.run'), saved })
  const classes = status?.mirror?.classes ?? []
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

  const askApply = () =>
    run(
      'count',
      () => api.get(`${path}/mirror`),
      (count) => setApplying(count),
    )
  const apply = () =>
    run(
      'apply',
      () => api.post(`${path}/mirror/apply`),
      (done) => {
        setApplying(null)
        setSaid(appliedText(done))
      },
    )

  const set = (patch) => onForm({ ...form, ...patch })
  const allow = (id, on) =>
    set({
      mirrorAllow: on ? [...new Set([...form.mirrorAllow, id])].sort() : form.mirrorAllow.filter((one) => one !== id),
    })
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
        becomes an incident, of the type the classifier gives and with the fields the mapper gives. A cycle whose time
        passed while the server was stopped runs once when it is back, and asks from where the last one reached: an
        alert becomes one incident, whatever was restarted in between.
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

      <fieldset className="flex flex-col gap-1.5 border-t border-line-soft pt-3">
        <legend className="float-left mb-1 w-full font-mono text-[11px] uppercase tracking-wider text-fg-muted">
          Mirroring
        </legend>
        <p className="text-xs text-fg-muted">
          The direction the incidents this instance fetches are kept in step with what they were made from. It is for
          the incidents fetched from now on, and can be changed on each incident. A mapper that names the object and the
          direction itself is obeyed first.
        </p>
        {choices.map((choice) => (
          <label
            key={choice.id}
            className={`flex items-start gap-2 text-sm ${choice.offered ? 'text-fg' : 'text-fg-subtle'}`}
          >
            <input
              type="radio"
              name="instance-mirror"
              value={choice.id}
              checked={(form.mirror ?? 'none') === choice.id}
              disabled={!choice.offered}
              onChange={() => set({ mirror: choice.id })}
              className="mt-1 accent-accent"
            />
            <span>
              {choice.label}
              <span className="block text-xs text-fg-muted">
                {choice.offered ? choice.text : `Not offered: ${choice.text}`}
              </span>
            </span>
          </label>
        ))}
        {sends(form.mirror) && (
          <div role="group" aria-label="What its mirrors may send" className="flex flex-col gap-1 pl-6">
            <p className="text-xs text-fg-muted">
              What is sent passes the data guard. Hashes, public indicators, verdicts and Nik&apos;s own ids always may;
              a mirror this instance starts may also send the classes ticked here, and nothing else.
            </p>
            {classes.length === 0 ? (
              <p className="text-xs text-fg-muted">The classes are chosen here once the instance is made.</p>
            ) : (
              classes.map((item) => (
                <label key={item.id} className="flex items-start gap-2 text-sm text-fg">
                  <input
                    type="checkbox"
                    checked={form.mirrorAllow.includes(item.id)}
                    onChange={(event) => allow(item.id, event.target.checked)}
                    className="mt-1 accent-accent"
                  />
                  <span>
                    {item.label}
                    <span className="block text-xs text-fg-muted">{item.warning}</span>
                  </span>
                </label>
              ))
            )}
          </div>
        )}
        {instance && (form.mirror ?? 'none') !== saved && (
          <p className="text-xs text-med-fg">
            Mirroring is {choiceLabel(saved)} until the instance is saved. Saving changes nothing for the incidents
            already fetched: that is asked for apart, below.
          </p>
        )}
      </fieldset>

      <fieldset className="flex flex-col gap-1.5 border-t border-line-soft pt-3">
        <legend className="float-left mb-1 w-full font-mono text-[11px] uppercase tracking-wider text-fg-muted">
          Indicators found
        </legend>
        <p className="text-xs text-fg-muted">
          Whether the incidents this instance fetches are read for indicators as they come in, and at each update a
          mirror brings. It follows the setting (Platform settings, Indicators found) unless it is told apart here.
        </p>
        {instance ? (
          <>
            <FindIndicatorsSwitch connectionId={instance.id} name={instance.name} />
            <p className="text-xs text-fg-muted">This choice is saved at once: it does not wait for Save.</p>
          </>
        ) : (
          <p className="text-xs text-fg-muted">It is chosen here once the instance is made.</p>
        )}
      </fieldset>

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
            {(connector.mirror || saved !== 'none') && (
              <Button
                waiting={busy === 'count'}
                variant="secondary"
                size="sm"
                icon={ArrowLeftRight}
                disabled={busy !== '' || (form.mirror ?? 'none') !== saved}
                title={
                  (form.mirror ?? 'none') !== saved ? 'Save the instance first: this applies what is saved' : undefined
                }
                onClick={askApply}
              >
                Apply mirroring to open incidents…
              </Button>
            )}
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
        open={applying !== null}
        onClose={() => setApplying(null)}
        title={`Mirror ${choiceLabel(saved)} what was already fetched?`}
        footer={
          <>
            <Button variant="secondary" onClick={() => setApplying(null)}>
              Cancel
            </Button>
            <Button waiting={busy === 'apply'} disabled={busy !== '' || !applying?.open} onClick={apply}>
              {saved === 'none' ? 'Stop mirroring them' : `Mirror them ${choiceLabel(saved)}`}
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg">{applyText(applying, saved)}</p>
        {sends(saved) && Boolean(applying?.open) && (
          <p className="mt-2 border border-med-line bg-med-soft px-3 py-2 text-xs text-med-fg">
            From then on, what changes in those incidents and their notes tagged <strong>mirror</strong> are sent to{' '}
            {instance?.name} without asking again. It is recorded.
          </p>
        )}
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
