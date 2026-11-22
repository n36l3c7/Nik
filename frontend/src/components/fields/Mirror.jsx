import { useCallback, useEffect, useState } from 'react'
import { ArrowLeftRight, RefreshCw } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { formatDateTime } from '../../lib/time.js'
import { api } from '../../services/api.js'
import { useUnsavedChanges } from '../../lib/unsaved.js'
import { DIRECTIONS, choiceLabel, mirrorProblem, mirrorTimes, originText } from '../../domain/fetch.js'
import { Button, Modal } from '../ui/index.js'

/*
 * Mirroring, in the side panel of an incident: whether the incident is kept
 * in step with an object of another product (a ticket, an issue), which way,
 * where that direction came from (the instance that fetched the incident, a
 * mapper, or a person here) and how it goes: the last read, the last send,
 * the last problem. Whoever writes incidents starts it, changes its
 * direction, reads the other side now, and stops it. Nothing is shown when no
 * connection can mirror.
 */

const INPUT =
  'w-full border border-line bg-canvas px-2 py-1.5 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const LABEL = 'text-xs font-medium text-fg-muted'

function StartDialog({ incident, connections, canSend, onClose, onStarted }) {
  const [instanceId, setConnectionId] = useState(connections[0]?.id ?? '')
  const [mirrorId, setMirrorId] = useState('')
  const [direction, setDirection] = useState('in')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const connection = connections.find((item) => item.id === instanceId)
  const problem = mirrorProblem({ connection, mirrorId, direction, canSend })
  // What was typed is not lost without asking (lib/unsaved.js): closing the dialog asks first.
  const unsaved = useUnsavedChanges(Boolean(mirrorId.trim()) && !busy, {
    what: 'The mirror being started',
    name: incident.name ?? '',
  })
  const close = () => unsaved.leave(onClose)

  const start = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      onStarted(
        await api.post(`/incidents/${encodeURIComponent(incident.id)}/mirror`, {
          instanceId,
          mirrorId: mirrorId.trim(),
          direction,
        }),
      )
    } catch (failure) {
      setError(failure.message)
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={close}
      title="Mirror this incident"
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={close} disabled={busy}>
            Cancel
          </Button>
          <Button type="submit" form="mirror-start" size="sm" disabled={busy || Boolean(problem)}>
            Start mirroring
          </Button>
        </>
      }
    >
      <form id="mirror-start" onSubmit={start} className="flex flex-col gap-3">
        <div className="flex flex-col gap-1">
          <label htmlFor="mirror-connection" className={LABEL}>
            With
          </label>
          <select
            id="mirror-connection"
            value={instanceId}
            onChange={(event) => setConnectionId(event.target.value)}
            className={`${INPUT} cursor-pointer`}
          >
            {connections.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name} ({item.connector})
              </option>
            ))}
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="mirror-id" className={LABEL}>
            The id of the object on the other side
          </label>
          <input
            id="mirror-id"
            type="text"
            value={mirrorId}
            autoComplete="off"
            spellCheck={false}
            placeholder="a ticket's id, an issue's key"
            onChange={(event) => setMirrorId(event.target.value)}
            className={`${INPUT} font-mono`}
          />
        </div>
        <fieldset className="flex flex-col gap-1.5">
          <legend className={LABEL}>Which way</legend>
          {DIRECTIONS.map((item) => (
            <label key={item.id} className="flex items-start gap-2 text-sm text-fg">
              <input
                type="radio"
                name="mirror-direction"
                value={item.id}
                checked={direction === item.id}
                onChange={() => setDirection(item.id)}
                className="mt-1 accent-accent"
              />
              <span>
                {item.label}
                <span className="block text-xs text-fg-muted">{item.hint}</span>
              </span>
            </label>
          ))}
        </fieldset>
        {direction !== 'in' && (
          <p className="border border-med-line bg-med-soft px-3 py-2 text-xs text-med-fg">
            From now on, what changes in this incident and its notes tagged <strong>mirror</strong> are sent to{' '}
            {connection?.name ?? 'the other side'} without asking again. What is sent passes the data guard, and
            starting is recorded.
          </p>
        )}
        {(error || problem) && (
          <p role={error ? 'alert' : 'status'} className={`text-sm ${error ? 'text-high-fg' : 'text-fg-muted'}`}>
            {error || problem}
          </p>
        )}
      </form>
    </Modal>
  )
}

/** @param {{ incident: object }} props */
export default function Mirror({ incident }) {
  const { can } = useAuth()
  const { retryActiveIncident } = useIncidents()
  const [state, setState] = useState(null)
  const [starting, setStarting] = useState(false)
  const [said, setSaid] = useState(null)
  const [error, setError] = useState(null)
  const id = incident.id

  const load = useCallback(async () => {
    try {
      setState(await api.get(`/incidents/${encodeURIComponent(id)}/mirror`))
    } catch {
      setState(null)
    }
  }, [id])
  useEffect(() => {
    setSaid(null)
    setError(null)
    load()
  }, [load])

  if (!state || (!state.mirrored && state.instances.length === 0)) return null
  const canWrite = can('write')
  const act = async (request, done) => {
    setError(null)
    setSaid(null)
    try {
      const answer = await request()
      setSaid(typeof done === 'function' ? done(answer) : done)
      await load()
      retryActiveIncident()
    } catch (failure) {
      setError(failure.message)
    }
  }
  const path = `/incidents/${encodeURIComponent(id)}/mirror`

  return (
    <section aria-label="Mirroring" className="flex flex-col gap-1.5 border-t border-line-soft pt-2">
      <p className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">Mirror</p>
      {state.mirrored ? (
        <>
          <p className="text-sm text-fg">
            {state.connection}
            <span className="block font-mono text-xs text-fg-muted">{state.id}</span>
          </p>
          <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-fg-muted">
            {canWrite ? (
              <select
                aria-label="Direction of the mirror"
                value={state.direction}
                onChange={(event) =>
                  act(
                    () => api.patch(path, { direction: event.target.value }),
                    `Mirroring is ${choiceLabel(event.target.value)} for this incident.`,
                  )
                }
                className="cursor-pointer border border-line bg-canvas px-1.5 py-0.5 text-xs text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                {DIRECTIONS.map((item) => (
                  <option
                    key={item.id}
                    value={item.id}
                    disabled={item.id !== 'in' && !(state.can?.fieldsOut || state.can?.commentsOut)}
                  >
                    {item.label}
                  </option>
                ))}
              </select>
            ) : (
              <span className="text-fg">{choiceLabel(state.direction)}</span>
            )}
            <span>{originText(state.origin)}</span>
          </p>
          <p className="text-xs text-fg-muted">{mirrorTimes(state, (stamp) => formatDateTime(Date.parse(stamp)))}</p>
          {state.error && <p className={`text-xs ${state.gone ? 'text-med-fg' : 'text-high-fg'}`}>{state.error}</p>}
          {canWrite && (
            <div className="flex flex-wrap gap-1.5">
              <Button
                variant="secondary"
                size="xs"
                icon={RefreshCw}
                disabled={state.fed}
                title={
                  state.fed ? 'Replies come with what the instance fetches: there is nothing to read now' : undefined
                }
                onClick={() =>
                  act(
                    () => api.post(`${path}/sync`),
                    (answer) =>
                      answer.gone
                        ? 'It is still gone on the other side.'
                        : answer.changed.length || answer.comments
                          ? `Read: ${answer.changed.length} field${answer.changed.length === 1 ? '' : 's'} changed, ${answer.comments} new comment${answer.comments === 1 ? '' : 's'}.`
                          : answer.kept.length
                            ? `Nothing changed: ${answer.kept.join(', ')} kept as set here.`
                            : 'Nothing new on the other side.',
                  )
                }
              >
                Read now
              </Button>
              <Button variant="ghost" size="xs" onClick={() => act(() => api.del(path), 'Mirroring stopped.')}>
                Stop
              </Button>
            </div>
          )}
        </>
      ) : (
        canWrite && (
          <Button
            variant="secondary"
            size="xs"
            icon={ArrowLeftRight}
            className="self-start"
            onClick={() => setStarting(true)}
          >
            Mirror with…
          </Button>
        )
      )}
      {(error || said) && (
        <p role={error ? 'alert' : 'status'} className={`text-xs ${error ? 'text-high-fg' : 'text-fg-muted'}`}>
          {error || said}
        </p>
      )}
      {starting && (
        <StartDialog
          incident={incident}
          connections={state.instances}
          canSend={can('automation.run')}
          onClose={() => setStarting(false)}
          onStarted={(next) => {
            setStarting(false)
            setState(next)
            setSaid('Mirroring started.')
            retryActiveIncident()
          }}
        />
      )}
    </section>
  )
}
