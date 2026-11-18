import { useEffect, useMemo, useState } from 'react'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { api } from '../../services/api.js'
import { UNCLASSIFIED, byName, fromInput, toInput } from '../../domain/fields.js'
import { Button, Modal } from '../ui/index.js'
import FieldInput from './FieldInput.jsx'

/*
 * Closing an incident: a reason among those of its type, notes, and the
 * fields the type wants filled before closing.
 *
 * Opened whenever an incident is set to "closed" (the Summary, the menu of
 * the list): `askClose(id)` of the incident context. The server checks the
 * same things, so an incident closed through the API is held to them too.
 */

const NOTES = { name: 'close_notes', label: 'Notes', type: 'long_text' }

export default function CloseIncidentDialog() {
  const { closeRequest, endClose } = useIncidents()
  // The dialog lives only while it is open: every closing starts from what the incident holds now.
  return closeRequest ? <OpenDialog key={closeRequest} incidentId={closeRequest} onDone={endClose} /> : null
}

function OpenDialog({ incidentId, onDone }) {
  const { incidents, activeIncidentId, refreshIncidents, retryActiveIncident } = useIncidents()
  const { showToast } = useToast()
  const [loaded, setLoaded] = useState(null) // { type, fields, values }
  const [typed, setTyped] = useState({})
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const name = incidents.find((incident) => incident.id === incidentId)?.name ?? 'this incident'

  useEffect(() => {
    let alive = true
    Promise.all([
      api.get(`/incidents/${encodeURIComponent(incidentId)}/fields`),
      api.get('/incident-types'),
      api.get('/fields'),
    ])
      .then(([held, types, registry]) => {
        if (!alive) return
        const type =
          types.types.find((item) => item.id === held.type) ??
          types.types.find((item) => item.id === UNCLASSIFIED) ??
          null
        const known = byName(registry.fields)
        const wanted = (type?.fields ?? [])
          .filter((item) => item.requiredOnClose && known[item.name])
          .map((item) => known[item.name])
        setLoaded({ type, wanted, values: held.fields })
        // A reason kept from an earlier closing is offered again only if this type still has it.
        const offered = type?.closeReasons ?? []
        const reason = held.fields.close_reason ?? ''
        setTyped({
          close_reason: offered.length && !offered.includes(reason) ? '' : reason,
          close_notes: held.fields.close_notes ?? '',
          ...Object.fromEntries(wanted.map((field) => [field.name, toInput(field, held.fields[field.name])])),
        })
      })
      .catch((failure) => alive && setError(failure.message))
    return () => {
      alive = false
    }
  }, [incidentId])

  const reasons = useMemo(() => loaded?.type?.closeReasons ?? [], [loaded])
  const reasonField = {
    name: 'close_reason',
    label: 'Reason',
    type: reasons.length ? 'choice' : 'text',
    options: { choices: reasons },
  }

  const submit = async (event) => {
    event.preventDefault()
    setError(null)
    const changes = { status: 'closed' }
    try {
      changes.close_reason = fromInput(reasonField, typed.close_reason)
      changes.close_notes = fromInput(NOTES, typed.close_notes)
      for (const field of loaded.wanted) {
        const value = fromInput(field, typed[field.name])
        if (value === null) throw new Error(`${field.label} is needed to close`)
        changes[field.name] = value
      }
    } catch (failure) {
      setError(failure.message)
      return
    }
    setBusy(true)
    try {
      await api.patch(`/incidents/${encodeURIComponent(incidentId)}/fields`, { changes })
      refreshIncidents()
      if (incidentId === activeIncidentId) retryActiveIncident()
      showToast({ message: 'Incident closed.' })
      onDone()
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={onDone}
      title="Close the incident"
      footer={
        <>
          <Button variant="secondary" onClick={onDone}>
            Cancel
          </Button>
          <Button type="submit" form="form-close-incident" disabled={busy || !loaded}>
            Close the incident
          </Button>
        </>
      }
    >
      <form id="form-close-incident" onSubmit={submit} className="flex flex-col gap-4 text-sm">
        <p className="text-fg-muted">
          <span className="text-fg">{name}</span>
          {loaded?.type ? ` · ${loaded.type.name}` : ''}
        </p>
        {!loaded && !error && (
          <p role="status" className="font-mono text-fg-muted">
            Loading…
          </p>
        )}
        {loaded && (
          <>
            <label className="flex flex-col gap-1" htmlFor="close-reason">
              <span className="text-fg-muted">Reason</span>
              <FieldInput
                id="close-reason"
                field={reasonField}
                value={typed.close_reason}
                onChange={(value) => setTyped({ ...typed, close_reason: value })}
              />
            </label>
            <label className="flex flex-col gap-1" htmlFor="close-notes">
              <span className="text-fg-muted">Notes</span>
              <FieldInput
                id="close-notes"
                field={NOTES}
                value={typed.close_notes}
                onChange={(value) => setTyped({ ...typed, close_notes: value })}
              />
            </label>
            {loaded.wanted.map((field) => (
              <label key={field.name} className="flex flex-col gap-1" htmlFor={`close-field-${field.name}`}>
                <span className="text-fg-muted">
                  {field.label}{' '}
                  <span className="text-med" title="Needed to close">
                    *
                  </span>
                </span>
                <FieldInput
                  id={`close-field-${field.name}`}
                  field={field}
                  value={typed[field.name]}
                  onChange={(value) => setTyped({ ...typed, [field.name]: value })}
                />
                {field.description && <span className="text-xs text-fg-muted">{field.description}</span>}
              </label>
            ))}
          </>
        )}
        {error && (
          <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-high-fg">
            {error}
          </p>
        )}
      </form>
    </Modal>
  )
}
