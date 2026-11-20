import { useEffect, useMemo, useState } from 'react'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useNavigation } from '../../context/NavigationContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { api } from '../../services/api.js'
import { UNCLASSIFIED, byName, fromInput, toInput } from '../../domain/fields.js'
import { closeFields, closeSections, openTasksText } from '../../domain/typePages.js'
import { Button, Modal } from '../ui/index.js'
import FieldInput from './FieldInput.jsx'
import { useUnsavedChanges } from '../../lib/unsaved.js'

/*
 * Closing an incident: a reason among those of its type, notes, and the
 * fields the type wants filled before closing.
 *
 * A type can give the dialog a **close form** (6.2: Settings → Incidents →
 * Types → Pages → Close form): sections of its own, shown here with their
 * fields to edit. A field the type marks "to close" is marked required and
 * holds the closing back while it is empty, wherever it is shown; one that is
 * in no section of the form is asked after them, as it always was. A line
 * says how many tasks of the work plan are still open: it stops nothing.
 *
 * Opened whenever an incident is set to "closed" (the Summary, the menu of
 * the list): `askClose(id)` of the incident context. The server checks the
 * same things, so an incident closed through the API is held to them too.
 */

const NOTES = { name: 'close_notes', label: 'Notes', type: 'long_text' }
const WIDE = new Set(['long_text', 'json', 'list', 'multi_choice'])
const same = (a, b) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null)

export default function CloseIncidentDialog() {
  const { closeRequest, endClose } = useIncidents()
  // The dialog lives only while it is open: every closing starts from what the incident holds now.
  return closeRequest ? <OpenDialog key={closeRequest} incidentId={closeRequest} onDone={endClose} /> : null
}

function Asked({ item, value, onChange }) {
  const { field, needed } = item
  const id = `close-field-${field.name}`
  return (
    <label className={`flex flex-col gap-1 ${WIDE.has(field.type) ? 'sm:col-span-2' : ''}`} htmlFor={id}>
      <span className="text-fg-muted">
        {field.label}
        {needed && (
          <span className="text-med" title="Needed to close">
            {' '}
            · required
          </span>
        )}
      </span>
      <FieldInput id={id} field={field} value={value} onChange={onChange} />
      {field.description && <span className="text-xs text-fg-muted">{field.description}</span>}
    </label>
  )
}

function OpenDialog({ incidentId, onDone }) {
  const { incidents, activeIncidentId, refreshIncidents, retryActiveIncident, selectIncident } = useIncidents()
  const { goTo } = useNavigation()
  const { showToast } = useToast()
  const [loaded, setLoaded] = useState(null) // { type, sections, wanted, values }
  const [openTasks, setOpenTasks] = useState(0)
  const [typed, setTyped] = useState({})
  const [opened, setOpened] = useState(null) // the form as it was filled from the incident
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const unsaved = useUnsavedChanges(opened !== null && JSON.stringify(typed) !== opened, {
    what: 'The form that closes the incident',
  })
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
        // The sections of the close form of the type, each with the fields it lets one edit.
        const sections = closeSections(type?.layout)
          .map((section) => ({ section, fields: closeFields(section, known, type?.fields) }))
          .filter((item) => item.fields.length > 0)
        const shown = new Set(sections.flatMap((item) => item.fields.map((asked) => asked.field.name)))
        // What the type wants to close with and no section shows: asked after them.
        const wanted = (type?.fields ?? [])
          .filter((item) => item.requiredOnClose && known[item.name] && !shown.has(item.name))
          .map((item) => ({ field: known[item.name], needed: true }))
        setLoaded({ type, sections, wanted, values: held.fields })
        // A reason kept from an earlier closing is offered again only if this type still has it.
        const offered = type?.closeReasons ?? []
        const reason = held.fields.close_reason ?? ''
        const asked = [...sections.flatMap((item) => item.fields), ...wanted]
        const start = {
          close_reason: offered.length && !offered.includes(reason) ? '' : reason,
          close_notes: held.fields.close_notes ?? '',
          ...Object.fromEntries(asked.map(({ field }) => [field.name, toInput(field, held.fields[field.name])])),
        }
        setTyped(start)
        setOpened(JSON.stringify(start))
      })
      .catch((failure) => alive && setError(failure.message))
    // How much of the work plan is left: said, never in the way (who may not read it is told nothing).
    api
      .get(`/incidents/${encodeURIComponent(incidentId)}/work-plan`)
      .then((plan) => alive && setOpenTasks(plan?.counts?.open ?? 0))
      .catch(() => {})
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
      const asked = [...loaded.sections.flatMap((item) => item.fields), ...loaded.wanted]
      for (const { field, needed } of asked) {
        const value = fromInput(field, typed[field.name])
        if (needed && value === null) throw new Error(`${field.label} is needed to close`)
        // A field of a section is sent when it was changed; what is needed to close, always.
        if (needed || !same(value, loaded.values[field.name])) changes[field.name] = value
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

  const showTasks = () => {
    onDone()
    if (incidentId !== activeIncidentId) selectIncident(incidentId)
    goTo('work_plan')
  }
  const set = (fieldName) => (value) => setTyped({ ...typed, [fieldName]: value })
  const form = (loaded?.sections.length ?? 0) > 0

  return (
    <Modal
      open
      onClose={() => unsaved.leave(onDone)}
      title="Close the incident"
      maxWidth={form ? 'max-w-2xl' : 'max-w-lg'}
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
          {form ? ' · the form of its type' : ''}
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
                onChange={set('close_reason')}
              />
            </label>
            {loaded.sections.map(({ section, fields }) => (
              <fieldset key={section.id} aria-label={`Section ${section.title}`} className="flex flex-col gap-2">
                <legend className="mb-2 font-mono text-[11px] uppercase tracking-wider text-fg-muted">
                  Section · {section.title}
                </legend>
                <div className={`grid gap-3 ${section.columns === 2 ? 'sm:grid-cols-2' : ''}`}>
                  {fields.map((item) => (
                    <Asked
                      key={item.field.name}
                      item={item}
                      value={typed[item.field.name]}
                      onChange={set(item.field.name)}
                    />
                  ))}
                </div>
              </fieldset>
            ))}
            {loaded.wanted.map((item) => (
              <Asked key={item.field.name} item={item} value={typed[item.field.name]} onChange={set(item.field.name)} />
            ))}
            {openTasks > 0 && (
              <div className="flex flex-wrap items-center gap-3 border border-med-line bg-med-soft px-3 py-2">
                <p role="status" className="min-w-0 flex-1 text-med-fg">
                  {openTasksText(openTasks)}
                </p>
                <Button variant="secondary" size="xs" onClick={showTasks}>
                  Show them
                </Button>
              </div>
            )}
            <label className="flex flex-col gap-1" htmlFor="close-notes">
              <span className="text-fg-muted">Notes</span>
              <FieldInput id="close-notes" field={NOTES} value={typed.close_notes} onChange={set('close_notes')} />
            </label>
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
