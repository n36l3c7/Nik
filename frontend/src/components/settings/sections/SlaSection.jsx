import { useEffect, useMemo, useState } from 'react'
import { api } from '../../../services/api.js'
import { useFields } from '../../../context/FieldsContext.jsx'
import { useSettings } from '../../../context/SettingsContext.jsx'
import { SEVERITIES, hoursText, slaOf, slaProblem, slaRows } from '../../../domain/timers.js'
import { Button, Wait } from '../../ui/index.js'
import { useUnsavedChanges } from '../../../lib/unsaved.js'

/*
 * Incidents → SLA (who configures incidents).
 *
 * For each type of incident, the time its incidents are allowed: to be
 * assigned, to be contained, to be closed, and any timer field of your own.
 * A timer that is switched on starts when an incident of the type is created
 * (or becomes of the type). Time to assign stops when the incident has an
 * owner, time to close when it is closed; the others are stopped by a
 * playbook or by hand. Past its time a timer is breached: the incident is
 * marked, its owner is told, and playbooks can start on `sla.breached`.
 */

const INPUT =
  'border border-line bg-canvas px-2 py-1 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50'

export default function SlaSection() {
  const { fields, types, reload } = useFields()
  const { businessHours } = useSettings()
  const [typeId, setTypeId] = useState('')
  const type = types.find((item) => item.id === typeId) ?? types[0] ?? null
  const [rows, setRows] = useState([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [saved, setSaved] = useState(false)

  const start = useMemo(() => slaRows(type, fields), [type, fields])
  useEffect(() => {
    setRows(start)
    setError(null)
  }, [start])
  // "Saved" is said of the type that was saved, until another is chosen or something is typed.
  const shownId = type?.id
  useEffect(() => {
    setSaved(false)
  }, [shownId])

  const change = (field, patch) => {
    setSaved(false)
    setRows((current) => current.map((row) => (row.field === field ? { ...row, ...patch } : row)))
  }
  const problem = slaProblem(rows)
  const dirty = JSON.stringify(slaOf(rows)) !== JSON.stringify(slaOf(start))

  // Resolves true once it is saved: the question asked before leaving waits on it.
  const save = async (event) => {
    event?.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.put(`/incident-types/${encodeURIComponent(type.id)}`, { sla: slaOf(rows) })
      await reload()
      setSaved(true)
      return true
    } catch (failure) {
      setError(failure.message)
      return false
    } finally {
      setBusy(false)
    }
  }
  const unsaved = useUnsavedChanges(dirty, {
    what: 'The SLA of the type',
    name: type?.name,
    save: problem ? undefined : save,
  })

  if (!type) {
    return <Wait>Loading the types…</Wait>
  }
  return (
    <form onSubmit={save} className="flex max-w-4xl flex-col gap-4">
      <p className="text-sm text-fg-muted">
        The time the incidents of a type are allowed. A timer that is on starts with the incident; past its time the
        incident is marked, its owner is told, and playbooks can start on{' '}
        <code className="font-mono">sla.breached</code>. Business hours are those of <em>Analysis → Business hours</em>
        {businessHours ? `: ${hoursText(businessHours)}` : ''}.
      </p>
      <label className="flex flex-col gap-1 self-start" htmlFor="sla-type">
        <span className="text-xs font-medium text-fg-muted">Type of incident</span>
        <select
          id="sla-type"
          value={type.id}
          onChange={(event) => {
            // Another type brings its own times: those typed for this one are asked about first.
            const next = event.target.value
            unsaved.leave(() => setTypeId(next))
          }}
          className={`${INPUT} cursor-pointer`}
        >
          {types.map((item) => (
            <option key={item.id} value={item.id}>
              {item.name}
              {item.sla?.length ? ` · ${item.sla.length} timed` : ''}
            </option>
          ))}
        </select>
      </label>

      <div className="overflow-x-auto border border-line">
        <table className="w-full min-w-[720px] border-collapse text-left text-sm">
          <caption className="sr-only">The SLA of {type.name}</caption>
          <thead className="bg-panel font-mono text-xs text-fg-muted">
            <tr>
              <th scope="col" className="border-b border-line px-3 py-1.5 font-normal">
                Timer
              </th>
              <th scope="col" className="border-b border-line px-3 py-1.5 font-normal">
                Minutes allowed
              </th>
              {SEVERITIES.map((name) => (
                <th key={name} scope="col" className="border-b border-line px-2 py-1.5 font-normal">
                  if {name}
                </th>
              ))}
              <th scope="col" className="border-b border-line px-3 py-1.5 font-normal">
                Business hours only
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.field}>
                <th scope="row" className="border-b border-line-soft px-3 py-2 font-normal">
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={row.on}
                      onChange={(event) => change(row.field, { on: event.target.checked })}
                      className="h-4 w-4 accent-accent"
                    />
                    <span>
                      {row.label}
                      <span className="block font-mono text-[11px] text-fg-subtle">{row.field}</span>
                    </span>
                  </label>
                </th>
                <td className="border-b border-line-soft px-3 py-2">
                  <input
                    type="text"
                    inputMode="numeric"
                    aria-label={`${row.label}: minutes allowed`}
                    value={row.minutes}
                    disabled={!row.on}
                    onChange={(event) => change(row.field, { minutes: event.target.value })}
                    className={`${INPUT} w-24 font-mono`}
                  />
                </td>
                {SEVERITIES.map((name) => (
                  <td key={name} className="border-b border-line-soft px-2 py-2">
                    <input
                      type="text"
                      inputMode="numeric"
                      aria-label={`${row.label}: minutes allowed if ${name}`}
                      value={row.bySeverity[name]}
                      disabled={!row.on}
                      placeholder="same"
                      onChange={(event) =>
                        change(row.field, { bySeverity: { ...row.bySeverity, [name]: event.target.value } })
                      }
                      className={`${INPUT} w-20 font-mono`}
                    />
                  </td>
                ))}
                <td className="border-b border-line-soft px-3 py-2">
                  <input
                    type="checkbox"
                    aria-label={`${row.label}: count business hours only`}
                    checked={row.businessHours}
                    disabled={!row.on}
                    onChange={(event) => change(row.field, { businessHours: event.target.checked })}
                    className="h-4 w-4 accent-accent"
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {(error || (dirty && problem)) && (
        <p role="alert" className="text-sm text-high-fg">
          {error || problem}
        </p>
      )}
      <div className="flex items-center gap-3">
        <Button type="submit" size="sm" disabled={busy || !dirty || Boolean(problem)}>
          Save the SLA of {type.name}
        </Button>
        {saved && !dirty && (
          <span role="status" className="text-sm text-fg-muted">
            Saved. It applies to the incidents of this type from now on, and to those still open.
          </span>
        )}
      </div>
    </form>
  )
}
