import { useCallback, useEffect, useState } from 'react'
import { Pause, Play, Square } from 'lucide-react'
import { useCanWrite } from '../../lib/useCanWrite.js'
import { useFields } from '../../context/FieldsContext.jsx'
import { api } from '../../services/api.js'
import { anyRunning, timerLine } from '../../domain/timers.js'

/*
 * The SLA timers of an incident, in its side panel: what each has counted
 * and what is left, read from the server (which knows the business hours).
 * Whoever writes incidents starts, pauses and stops one by hand. Nothing is
 * shown for an incident no timer was started on.
 */

const REFRESH_MS = 30_000
const TONES = { ok: 'text-fg', late: 'text-high', muted: 'text-fg-muted' }

function Move({ icon: Icon, label, onClick }) {
  return (
    <button
      type="button"
      title={label}
      aria-label={label}
      onClick={onClick}
      className="p-1 text-fg-muted hover:bg-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
    >
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
    </button>
  )
}

/** @param {{ incident: object }} props */
export default function Timers({ incident }) {
  const canWrite = useCanWrite(incident)
  // The types are read again when the SLA of one is saved: the timers follow.
  const { types } = useFields()
  const [timers, setTimers] = useState([])
  const [error, setError] = useState(null)
  const id = incident.id
  // An owner, a closing, another severity: the timers follow what the incident becomes.
  const stamp = `${incident.status}|${incident.assignee}|${incident.severity}|${incident.type ?? ''}`

  const load = useCallback(async () => {
    try {
      setTimers((await api.get(`/incidents/${encodeURIComponent(id)}/timers`)).timers)
    } catch {
      setTimers([])
    }
  }, [id])
  useEffect(() => {
    load()
  }, [load, stamp, types])
  const running = anyRunning(timers)
  useEffect(() => {
    if (!running) return undefined
    const timer = setInterval(() => document.visibilityState === 'visible' && load(), REFRESH_MS)
    return () => clearInterval(timer)
  }, [running, load])

  const move = async (field, what) => {
    setError(null)
    try {
      setTimers(
        (await api.post(`/incidents/${encodeURIComponent(id)}/timers/${encodeURIComponent(field)}/${what}`, {})).timers,
      )
    } catch (failure) {
      setError(failure.message)
    }
  }

  if (timers.length === 0) return null
  return (
    <section aria-label="SLA timers" className="flex flex-col gap-1.5 border-t border-line-soft pt-2">
      <p className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">SLA</p>
      <ul className="flex flex-col gap-1.5">
        {timers.map((timer) => {
          const line = timerLine(timer)
          return (
            <li key={timer.field} className="flex items-start justify-between gap-1">
              <span className="min-w-0">
                <span className="block text-xs text-fg-muted">
                  {timer.label}
                  {timer.business ? ' · business hours' : ''}
                </span>
                <span className={`block text-sm ${TONES[line.tone]}`}>{line.text}</span>
              </span>
              {canWrite && (
                <span className="flex shrink-0">
                  {timer.state === 'running' ? (
                    <Move icon={Pause} label={`Pause ${timer.label}`} onClick={() => move(timer.field, 'pause')} />
                  ) : (
                    <Move icon={Play} label={`Start ${timer.label}`} onClick={() => move(timer.field, 'start')} />
                  )}
                  {timer.state !== 'stopped' && (
                    <Move icon={Square} label={`Stop ${timer.label}`} onClick={() => move(timer.field, 'stop')} />
                  )}
                </span>
              )}
            </li>
          )
        })}
      </ul>
      {error && (
        <p role="alert" className="text-xs text-high-fg">
          {error}
        </p>
      )}
    </section>
  )
}
