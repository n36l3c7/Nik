import { useState } from 'react'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { api } from '../../services/api.js'
import { changesOf, isRequired, toInput } from '../../domain/fields.js'
import { Button, Modal } from '../ui/index.js'
import FieldInput from './FieldInput.jsx'

/*
 * A form for some fields of an incident: those of a section of its page, or
 * of its side panel. It sends only what changed, through the field registry
 * (PATCH /api/incidents/<id>/fields), which checks every value; what the
 * server refuses is said here, and nothing is saved.
 */

/**
 * @param {{
 *   incident: object,
 *   type: object | null,
 *   title: string,
 *   fields: object[],            // the fields of the registry to edit, in order
 *   values: object,              // what the incident holds now, by name
 *   onClose: () => void,
 * }} props
 */
export default function EditFieldsDialog({ incident, type, title, fields, values, onClose }) {
  const { assignees, refreshIncidents, retryActiveIncident } = useIncidents()
  const editable = fields.filter((field) => field.writable !== false && field.name !== 'type')
  const [typed, setTyped] = useState(() =>
    Object.fromEntries(editable.map((field) => [field.name, toInput(field, values[field.name])])),
  )
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  const submit = async (event) => {
    event.preventDefault()
    setError(null)
    let changes
    try {
      changes = changesOf(type, editable, typed, values)
    } catch (failure) {
      setError(failure.message)
      return
    }
    if (Object.keys(changes).length === 0) {
      onClose()
      return
    }
    setBusy(true)
    try {
      await api.patch(`/incidents/${encodeURIComponent(incident.id)}/fields`, { changes })
      // The server wrote them: the copy held here is read again.
      refreshIncidents()
      retryActiveIncident()
      onClose()
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={title}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="form-edit-fields" disabled={busy}>
            Save
          </Button>
        </>
      }
    >
      <form id="form-edit-fields" onSubmit={submit} className="flex flex-col gap-4 text-sm">
        {editable.map((field) => (
          <div key={field.name} className="flex flex-col gap-1">
            <label className="text-fg-muted" htmlFor={`edit-${field.name}`}>
              {field.label}
              {isRequired(type, field.name) && (
                <span className="text-med" title="Required">
                  {' '}
                  *
                </span>
              )}
            </label>
            <FieldInput
              id={`edit-${field.name}`}
              field={field}
              value={typed[field.name]}
              users={field.type === 'user' ? assignees : null}
              onChange={(value) => setTyped({ ...typed, [field.name]: value })}
            />
            {field.description && <span className="text-xs text-fg-muted">{field.description}</span>}
          </div>
        ))}
        {error && (
          <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-high-fg">
            {error}
          </p>
        )}
      </form>
    </Modal>
  )
}
