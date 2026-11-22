import { useCallback, useEffect, useMemo, useState } from 'react'
import { Pencil, Plus, Trash2 } from 'lucide-react'
import { api } from '../../../services/api.js'
import { useFields } from '../../../context/FieldsContext.jsx'
import { FIELD_TYPES } from '../../../domain/fields.js'
import { Badge, Button, Modal, SearchInput, Wait } from '../../ui/index.js'
import NewFieldDialog from '../../fields/NewFieldDialog.jsx'
import { useUnsavedChanges } from '../../../lib/unsaved.js'

/*
 * Incidents → All fields (who configures incidents).
 *
 * The registry as a whole: every field an incident can hold, with its name,
 * its type and where it is used. A field has one name for one thing, whoever
 * sets it, so the name and the type never change; the label, the description
 * and the choices do. A custom field no type lists and no incident holds can
 * be deleted. Which fields a type has, and where they are on its page, is
 * chosen in Types.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

function EditField({ field, onClose, onSaved }) {
  const [label, setLabel] = useState(field.label)
  const [description, setDescription] = useState(field.description ?? '')
  const withChoices = !field.system && (field.type === 'choice' || field.type === 'multi_choice')
  const [choices, setChoices] = useState((field.options?.choices ?? []).join('\n'))
  const [everywhere, setEverywhere] = useState(Boolean(field.allTypes))
  const [used, setUsed] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let alive = true
    api
      .get(`/fields/${encodeURIComponent(field.name)}`)
      .then((found) => alive && setUsed(found.usedBy))
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [field.name])

  const unsaved = useUnsavedChanges(
    label !== field.label ||
      description !== (field.description ?? '') ||
      (withChoices && choices !== (field.options?.choices ?? []).join('\n')) ||
      (!field.system && everywhere !== Boolean(field.allTypes)),
    { what: 'The field', name: field.label },
  )
  const submit = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    const body = { label: label.trim(), description }
    if (withChoices) {
      body.options = {
        choices: choices
          .split('\n')
          .map((line) => line.trim())
          .filter(Boolean),
      }
    }
    if (!field.system) body.allTypes = everywhere
    try {
      onSaved(await api.patch(`/fields/${encodeURIComponent(field.name)}`, body))
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={() => unsaved.leave(onClose)}
      title={`Field ${field.name}`}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="form-edit-field" disabled={busy || !label.trim()}>
            Save
          </Button>
        </>
      }
    >
      <form id="form-edit-field" onSubmit={submit} className="flex flex-col gap-4 text-sm">
        <p className="text-fg-muted">
          <span className="font-mono text-fg">{field.name}</span> · {FIELD_TYPES[field.type] ?? field.type}
          {field.system ? ' · a system field' : ''}. The name and the type do not change.
        </p>
        <label className="flex flex-col gap-1" htmlFor="edit-field-label">
          <span className="text-fg-muted">Label</span>
          <input
            id="edit-field-label"
            type="text"
            value={label}
            maxLength={80}
            autoComplete="off"
            onChange={(event) => setLabel(event.target.value)}
            className={INPUT}
          />
        </label>
        <label className="flex flex-col gap-1" htmlFor="edit-field-description">
          <span className="text-fg-muted">What it is for</span>
          <input
            id="edit-field-description"
            type="text"
            value={description}
            maxLength={1000}
            autoComplete="off"
            onChange={(event) => setDescription(event.target.value)}
            className={INPUT}
          />
        </label>
        {withChoices && (
          <label className="flex flex-col gap-1" htmlFor="edit-field-choices">
            <span className="text-fg-muted">Choices, one per line</span>
            <textarea
              id="edit-field-choices"
              value={choices}
              rows={5}
              onChange={(event) => setChoices(event.target.value)}
              className={`${INPUT} resize-y`}
            />
            <span className="text-xs text-fg-muted">
              A choice taken away stays on the incidents that hold it, and can no longer be chosen.
            </span>
          </label>
        )}
        {!field.system && (
          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              checked={everywhere}
              onChange={(event) => setEverywhere(event.target.checked)}
              className="mt-1 accent-accent"
            />
            <span>On every type of incident</span>
          </label>
        )}
        <p className="text-xs text-fg-muted" aria-live="polite">
          {used === null
            ? 'Looking where it is used…'
            : used.types.length === 0 && used.incidents === 0
              ? field.system
                ? 'On every type.'
                : 'No type lists it and no incident holds a value of it.'
              : [
                  used.types.length ? `Listed by: ${used.types.join(', ')}.` : field.system ? 'On every type.' : '',
                  used.incidents ? `${used.incidents} incident${used.incidents === 1 ? '' : 's'} hold a value.` : '',
                ]
                  .filter(Boolean)
                  .join(' ')}
        </p>
        {error && (
          <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-high-fg">
            {error}
          </p>
        )}
      </form>
    </Modal>
  )
}

export default function FieldsSection() {
  const [fields, setFields] = useState(null)
  const [error, setError] = useState(null)
  const [query, setQuery] = useState('')
  const [creating, setCreating] = useState(false)
  const [editing, setEditing] = useState(null)
  const [deleting, setDeleting] = useState(null)

  const { reload: reloadShared } = useFields()
  const load = useCallback(async () => {
    try {
      setFields((await api.get('/fields')).fields)
      reloadShared()
    } catch (failure) {
      setError(failure.message)
    }
  }, [reloadShared])
  useEffect(() => {
    load()
  }, [load])

  const shown = useMemo(() => {
    const words = query.trim().toLowerCase()
    return (fields ?? []).filter(
      (field) =>
        !words ||
        `${field.name} ${field.label} ${field.description} ${FIELD_TYPES[field.type] ?? ''}`
          .toLowerCase()
          .includes(words),
    )
  }, [fields, query])

  const remove = async () => {
    try {
      await api.del(`/fields/${encodeURIComponent(deleting.name)}`)
      setDeleting(null)
      setError(null)
      load()
    } catch (failure) {
      setDeleting(null)
      setError(failure.message)
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-fg-muted">
        Every field an incident can hold. A field has one name for one thing, whoever sets it: a person, a playbook, a
        connector. Which fields a type of incident has, and where they are on its page, is chosen in{' '}
        <strong className="text-fg">Types</strong>.
      </p>
      <div className="flex flex-wrap items-center gap-3">
        <div className="min-w-[220px] flex-1">
          <SearchInput value={query} onChange={setQuery} placeholder="Find a field…" />
        </div>
        <Button size="sm" icon={Plus} onClick={() => setCreating(true)}>
          New field
        </Button>
      </div>
      {error && (
        <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
          {error}
        </p>
      )}
      {!fields && !error && <Wait>Loading the fields…</Wait>}
      {fields && (
        <div className="overflow-x-auto border border-line">
          <table className="w-full min-w-[640px] border-collapse text-left text-sm">
            <caption className="sr-only">All fields</caption>
            <thead className="bg-panel font-mono text-xs text-fg-muted">
              <tr>
                {['Label', 'Name', 'Type', 'On', ''].map((heading) => (
                  <th key={heading} scope="col" className="border-b border-line px-3 py-1.5 font-normal">
                    {heading || <span className="sr-only">Actions</span>}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {shown.map((field) => (
                <tr key={field.name} className="hover:bg-raised/40">
                  <th scope="row" className="border-b border-line-soft px-3 py-2 font-normal text-fg">
                    {field.label}
                    {field.description && <span className="block text-xs text-fg-muted">{field.description}</span>}
                  </th>
                  <td className="border-b border-line-soft px-3 py-2 font-mono text-xs text-fg-muted">{field.name}</td>
                  <td className="border-b border-line-soft px-3 py-2 text-fg-muted">
                    {FIELD_TYPES[field.type] ?? field.type}
                  </td>
                  <td className="border-b border-line-soft px-3 py-2">
                    {field.system ? (
                      <Badge color="slate">system</Badge>
                    ) : field.allTypes ? (
                      <Badge color="cyan">every type</Badge>
                    ) : (
                      <span className="text-xs text-fg-muted">the types that list it</span>
                    )}
                  </td>
                  <td className="border-b border-line-soft px-3 py-2">
                    <span className="flex justify-end gap-1">
                      <Button
                        variant="ghost"
                        size="xs"
                        icon={Pencil}
                        aria-label={`Edit the field ${field.label}`}
                        onClick={() => setEditing(field)}
                      />
                      {!field.system && (
                        <Button
                          variant="ghost"
                          size="xs"
                          icon={Trash2}
                          aria-label={`Delete the field ${field.label}`}
                          onClick={() => setDeleting(field)}
                        />
                      )}
                    </span>
                  </td>
                </tr>
              ))}
              {shown.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-4 text-center text-sm text-fg-muted">
                    {query.trim() ? 'No field matches.' : 'No field yet.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {creating && (
        <NewFieldDialog
          fields={fields ?? []}
          onClose={() => setCreating(false)}
          onCreated={() => {
            setCreating(false)
            load()
          }}
        />
      )}
      {editing && (
        <EditField
          field={editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null)
            load()
          }}
        />
      )}
      <Modal
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        title="Delete the field?"
        footer={
          <>
            <Button variant="secondary" onClick={() => setDeleting(null)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={remove}>
              Delete
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg">
          <span className="font-mono">{deleting?.name}</span> is deleted only if no type lists it and no incident holds
          a value of it: otherwise Nik says where it is used.
        </p>
      </Modal>
    </div>
  )
}
