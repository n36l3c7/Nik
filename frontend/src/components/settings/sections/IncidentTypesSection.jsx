import { useCallback, useEffect, useMemo, useState } from 'react'
import { ArrowDown, ArrowLeft, ArrowUp, GripVertical, PanelLeft, Plus, Trash2, X } from 'lucide-react'
import { api } from '../../../services/api.js'
import { useFields } from '../../../context/FieldsContext.jsx'
import {
  FIELD_TYPES,
  UNCLASSIFIED,
  addSection,
  byName,
  moveField,
  moveSection,
  placeField,
  removeSection,
  setFieldFlags,
  typePayload,
  unplaceField,
  unplaced,
  updateSection,
} from '../../../domain/fields.js'
import { Badge, Button, Modal, SearchInput } from '../../ui/index.js'
import NewFieldDialog from '../../fields/NewFieldDialog.jsx'
import TypePagesEditor from './TypePagesEditor.jsx'
import { useUnsavedChanges } from '../../../lib/unsaved.js'

/*
 * ============================================================================
 * Incidents → Types (who configures incidents)
 * ============================================================================
 *
 * A type of incident says which fields its incidents have, where they are on
 * the page, and how one is closed. The list shows the types; a type opens in
 * the builder:
 *
 *   left    the registry, as a list to search: a field is added to the
 *           section chosen on the right with a click, with Enter, or by
 *           dragging it there. "New field" makes one.
 *   right   the sections of the Summary. One of them can be the side panel
 *           of the incident page. Fields are reordered by dragging or with
 *           the arrows; a field of your own can be required, or required
 *           before closing.
 *   below   the reasons an incident of this type is closed with.
 *
 * That is the part "Fields and sections". The part "Pages" (6.2) is where the
 * tabs of the incident are ordered and hidden, the Summary and the pages of
 * the type are arranged, and its close form and quick view are chosen
 * (TypePagesEditor.jsx).
 *
 * Nothing is saved until "Save the type". A field taken off the page stays
 * on the incidents that hold it: it is hidden, not deleted.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const DRAG = 'application/x-nik-field'
// The builder in two parts: what an incident of the type holds, and the pages that show it.
const PARTS = [
  { id: 'fields', label: 'Fields and sections' },
  { id: 'pages', label: 'Pages' },
]

/** The custom fields a type lists: those placed on its page, with the flags they have. */
function fieldsToSave(type, known) {
  const placed = new Set((type.layout?.sections ?? []).flatMap((section) => section.fields))
  const flags = Object.fromEntries((type.fields ?? []).map((item) => [item.name, item]))
  return [...placed]
    .filter((name) => known[name] && !known[name].system)
    .filter((name) => !known[name].allTypes || flags[name]?.required || flags[name]?.requiredOnClose)
    .map((name) => ({
      name,
      required: Boolean(flags[name]?.required),
      requiredOnClose: Boolean(flags[name]?.requiredOnClose),
    }))
}

function Builder({ type: saved, fields, colours, types, onBack, onSaved, onDeleted, onFieldCreated }) {
  const [type, setType] = useState(saved)
  const [target, setTarget] = useState(
    () => saved.layout.sections.find((section) => !section.key)?.id ?? saved.layout.sections[0]?.id ?? null,
  )
  const [query, setQuery] = useState('')
  const [newField, setNewField] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [moveTo, setMoveTo] = useState(UNCLASSIFIED)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [reasons, setReasons] = useState((saved.closeReasons ?? []).join('\n'))
  const [view, setView] = useState('fields')

  const known = useMemo(() => byName(fields), [fields])
  const layout = type.layout
  const dirty =
    JSON.stringify(typePayload({ ...type, closeReasons: reasons.split('\n') })) !== JSON.stringify(typePayload(saved))
  const setLayout = (next) => setType((current) => ({ ...current, layout: next }))
  const flagsOf = (name) => (type.fields ?? []).find((item) => item.name === name) ?? {}

  const offered = useMemo(() => {
    const words = query.trim().toLowerCase()
    return unplaced(type, fields).filter(
      (field) => !words || `${field.label} ${field.name} ${field.description ?? ''}`.toLowerCase().includes(words),
    )
  }, [type, fields, query])

  const add = (name, sectionId = target, index = null) => {
    const section = sectionId ?? layout.sections[layout.sections.length - 1]?.id
    if (!section) return
    setLayout(placeField(layout, name, section, index))
  }
  const drop = (event, sectionId, index = null) => {
    const name = event.dataTransfer.getData(DRAG)
    if (!name) return
    event.preventDefault()
    event.stopPropagation()
    add(name, sectionId, index)
  }

  const save = async () => {
    setBusy(true)
    setError(null)
    const body = typePayload({ ...type, closeReasons: reasons.split('\n'), fields: fieldsToSave(type, known) })
    try {
      const answer = await api.put(`/incident-types/${encodeURIComponent(type.id)}`, body)
      setType(answer)
      setReasons((answer.closeReasons ?? []).join('\n'))
      onSaved(answer)
      return true
    } catch (failure) {
      setError(failure.message)
      return false
    } finally {
      setBusy(false)
    }
  }
  const unsaved = useUnsavedChanges(dirty, {
    what: 'The type of incident',
    name: saved.name,
    save: String(type.name).trim() ? () => save() : undefined,
  })
  const remove = async () => {
    setBusy(true)
    try {
      await api.del(`/incident-types/${encodeURIComponent(type.id)}?moveTo=${encodeURIComponent(moveTo)}`)
      onDeleted()
    } catch (failure) {
      setError(failure.message)
      setDeleting(false)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="ghost" size="sm" icon={ArrowLeft} onClick={() => unsaved.leave(onBack)}>
          All types
        </Button>
        <span className="flex-1" />
        {dirty && <span className="font-mono text-xs text-med-fg">not saved</span>}
        {type.id !== UNCLASSIFIED && (
          <Button variant="ghost" size="sm" icon={Trash2} onClick={() => setDeleting(true)}>
            Delete the type
          </Button>
        )}
        <Button size="sm" disabled={busy || !dirty || !String(type.name).trim()} onClick={save}>
          Save the type
        </Button>
      </div>
      {error && (
        <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
          {error}
        </p>
      )}

      <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_160px]">
        <label className="flex flex-col gap-1 text-sm" htmlFor="type-name">
          <span className="text-fg-muted">Name</span>
          <input
            id="type-name"
            type="text"
            value={type.name}
            maxLength={80}
            autoComplete="off"
            onChange={(event) => setType({ ...type, name: event.target.value })}
            className={INPUT}
          />
        </label>
        <label className="flex flex-col gap-1 text-sm" htmlFor="type-colour">
          <span className="text-fg-muted">Colour</span>
          <select
            id="type-colour"
            value={type.colour}
            onChange={(event) => setType({ ...type, colour: event.target.value })}
            className={`${INPUT} cursor-pointer`}
          >
            {colours.map((colour) => (
              <option key={colour} value={colour}>
                {colour}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-sm sm:col-span-2" htmlFor="type-description">
          <span className="text-fg-muted">What it is for</span>
          <input
            id="type-description"
            type="text"
            value={type.description ?? ''}
            maxLength={1000}
            autoComplete="off"
            onChange={(event) => setType({ ...type, description: event.target.value })}
            className={INPUT}
          />
        </label>
      </div>

      <div role="tablist" aria-label="Parts of the type" className="flex gap-1 border-b border-line">
        {PARTS.map((part) => (
          <button
            key={part.id}
            type="button"
            role="tab"
            id={`type-part-${part.id}`}
            aria-selected={view === part.id}
            aria-controls="type-part-panel"
            onClick={() => setView(part.id)}
            className={`-mb-px border-b-2 px-3 py-2 font-mono text-[13px] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
              view === part.id
                ? 'border-accent text-fg'
                : 'border-transparent text-fg-muted hover:border-line hover:text-fg'
            }`}
          >
            {part.label}
          </button>
        ))}
      </div>

      <div id="type-part-panel" role="tabpanel" aria-labelledby={`type-part-${view}`} className="flex flex-col gap-4">
        {view === 'pages' && (
          <TypePagesEditor type={type} layout={layout} onLayout={setLayout} fields={fields} known={known} />
        )}
        {view === 'fields' && (
          <div className="grid items-start gap-4 lg:grid-cols-[260px_minmax(0,1fr)]">
            <section aria-label="Fields to add" className="flex flex-col gap-2 border border-line bg-panel p-3">
              <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">Fields</h3>
              <SearchInput value={query} onChange={setQuery} placeholder="Find a field…" />
              <ul className="flex max-h-[420px] flex-col gap-1 overflow-y-auto">
                {offered.map((field) => (
                  <li key={field.name}>
                    <button
                      type="button"
                      draggable
                      onDragStart={(event) => event.dataTransfer.setData(DRAG, field.name)}
                      onClick={() => add(field.name)}
                      title={`Add ${field.label} to the chosen section`}
                      className="flex w-full items-center gap-2 border border-line-soft bg-canvas px-2 py-1 text-left text-sm text-fg hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    >
                      <Plus className="h-3.5 w-3.5 shrink-0 text-fg-muted" aria-hidden="true" />
                      <span className="min-w-0 flex-1 truncate">{field.label}</span>
                      <span className="shrink-0 font-mono text-[10px] text-fg-muted">
                        {FIELD_TYPES[field.type] ?? field.type}
                      </span>
                    </button>
                  </li>
                ))}
                {offered.length === 0 && (
                  <li className="px-1 py-2 text-xs text-fg-muted">
                    {query ? 'No field matches.' : 'Every field is on the page.'}
                  </li>
                )}
              </ul>
              <Button variant="secondary" size="sm" icon={Plus} onClick={() => setNewField(true)}>
                New field
              </Button>
              <p className="text-xs text-fg-muted">A click adds the field to the section marked “adding here”.</p>
            </section>

            <div className="flex min-w-0 flex-col gap-3">
              {layout.sections.map((section, at) => (
                <section
                  key={section.id}
                  aria-label={`Section ${section.title}`}
                  onDragOver={(event) => event.dataTransfer.types.includes(DRAG) && event.preventDefault()}
                  onDrop={(event) => drop(event, section.id)}
                  className={`flex flex-col gap-2 border bg-panel p-3 ${target === section.id ? 'border-accent-strong' : 'border-line'}`}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <input
                      type="text"
                      aria-label="Title of the section"
                      value={section.title}
                      maxLength={80}
                      onChange={(event) => setLayout(updateSection(layout, section.id, { title: event.target.value }))}
                      className={`${INPUT} min-w-[160px] flex-1 font-semibold`}
                    />
                    <label className="flex items-center gap-1.5 text-xs text-fg-muted">
                      <input
                        type="checkbox"
                        checked={Boolean(section.key)}
                        onChange={(event) =>
                          setLayout(updateSection(layout, section.id, { key: event.target.checked }))
                        }
                        className="accent-accent"
                      />
                      <PanelLeft className="h-3.5 w-3.5" aria-hidden="true" />
                      Side panel
                    </label>
                    <select
                      aria-label="Columns of the section"
                      value={section.columns}
                      onChange={(event) =>
                        setLayout(updateSection(layout, section.id, { columns: Number(event.target.value) }))
                      }
                      className="cursor-pointer border border-line bg-canvas px-2 py-1 text-xs text-fg"
                    >
                      <option value={1}>1 column</option>
                      <option value={2}>2 columns</option>
                    </select>
                    <Button
                      variant={target === section.id ? 'secondary' : 'ghost'}
                      size="xs"
                      aria-pressed={target === section.id}
                      onClick={() => setTarget(section.id)}
                    >
                      {target === section.id ? 'Adding here' : 'Add here'}
                    </Button>
                    <Button
                      variant="ghost"
                      size="xs"
                      icon={ArrowUp}
                      aria-label={`Move the section ${section.title} up`}
                      disabled={at === 0}
                      onClick={() => setLayout(moveSection(layout, section.id, -1))}
                    />
                    <Button
                      variant="ghost"
                      size="xs"
                      icon={ArrowDown}
                      aria-label={`Move the section ${section.title} down`}
                      disabled={at === layout.sections.length - 1}
                      onClick={() => setLayout(moveSection(layout, section.id, 1))}
                    />
                    <Button
                      variant="ghost"
                      size="xs"
                      icon={Trash2}
                      aria-label={`Remove the section ${section.title}`}
                      onClick={() => setLayout(removeSection(layout, section.id))}
                    />
                  </div>
                  <ul className="flex flex-col gap-1">
                    {section.fields.map((name, index) => {
                      const field = known[name]
                      if (!field) return null
                      const flags = flagsOf(name)
                      return (
                        <li
                          key={name}
                          draggable
                          onDragStart={(event) => event.dataTransfer.setData(DRAG, name)}
                          onDragOver={(event) => event.dataTransfer.types.includes(DRAG) && event.preventDefault()}
                          onDrop={(event) => drop(event, section.id, index)}
                          className="flex flex-wrap items-center gap-2 border border-line-soft bg-canvas px-2 py-1 text-sm"
                        >
                          <GripVertical
                            className="h-3.5 w-3.5 shrink-0 cursor-grab text-fg-subtle"
                            aria-hidden="true"
                          />
                          <span className="min-w-0 flex-1 truncate text-fg">
                            {field.label}
                            <span className="ml-2 font-mono text-[10px] text-fg-muted">
                              {FIELD_TYPES[field.type] ?? field.type}
                            </span>
                          </span>
                          {!field.system && (
                            <>
                              <label className="flex items-center gap-1 text-xs text-fg-muted">
                                <input
                                  type="checkbox"
                                  checked={Boolean(flags.required)}
                                  onChange={(event) =>
                                    setType({
                                      ...type,
                                      fields: setFieldFlags(type.fields, name, { required: event.target.checked }),
                                    })
                                  }
                                  className="accent-accent"
                                />
                                required
                              </label>
                              <label className="flex items-center gap-1 text-xs text-fg-muted">
                                <input
                                  type="checkbox"
                                  checked={Boolean(flags.requiredOnClose)}
                                  onChange={(event) =>
                                    setType({
                                      ...type,
                                      fields: setFieldFlags(type.fields, name, {
                                        requiredOnClose: event.target.checked,
                                      }),
                                    })
                                  }
                                  className="accent-accent"
                                />
                                to close
                              </label>
                            </>
                          )}
                          <Button
                            variant="ghost"
                            size="xs"
                            icon={ArrowUp}
                            aria-label={`Move ${field.label} up`}
                            onClick={() => setLayout(moveField(layout, name, -1))}
                          />
                          <Button
                            variant="ghost"
                            size="xs"
                            icon={ArrowDown}
                            aria-label={`Move ${field.label} down`}
                            onClick={() => setLayout(moveField(layout, name, 1))}
                          />
                          <Button
                            variant="ghost"
                            size="xs"
                            icon={X}
                            aria-label={`Take ${field.label} off the page`}
                            onClick={() => setLayout(unplaceField(layout, name))}
                          />
                        </li>
                      )
                    })}
                    {section.fields.length === 0 && (
                      <li className="border border-dashed border-line px-2 py-3 text-center text-xs text-fg-muted">
                        No field yet: add one from the list, or drag it here.
                      </li>
                    )}
                  </ul>
                </section>
              ))}
              <Button
                variant="secondary"
                size="sm"
                icon={Plus}
                className="self-start"
                onClick={() => {
                  const next = addSection(layout)
                  setLayout(next)
                  setTarget(next.sections[next.sections.length - 1].id)
                }}
              >
                Add a section
              </Button>

              <label className="flex flex-col gap-1 text-sm" htmlFor="type-reasons">
                <span className="text-fg-muted">Close reasons, one per line</span>
                <textarea
                  id="type-reasons"
                  value={reasons}
                  rows={4}
                  onChange={(event) => setReasons(event.target.value)}
                  className={`${INPUT} resize-y`}
                />
                <span className="text-xs text-fg-muted">
                  What the form of closing offers. With none, any reason can be written.
                </span>
              </label>
            </div>
          </div>
        )}
      </div>

      {newField && (
        <NewFieldDialog
          fields={fields}
          onClose={() => setNewField(false)}
          onCreated={(made) => {
            setNewField(false)
            onFieldCreated(made)
            add(made.name)
          }}
        />
      )}
      <Modal
        open={deleting}
        onClose={() => setDeleting(false)}
        title={`Delete the type ${saved.name}?`}
        footer={
          <>
            <Button variant="secondary" onClick={() => setDeleting(false)}>
              Cancel
            </Button>
            <Button variant="danger" disabled={busy} onClick={remove}>
              Delete
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-3 text-sm text-fg">
          <p>
            {saved.incidents > 0
              ? `Its ${saved.incidents} incident${saved.incidents === 1 ? '' : 's'} take another type and keep every value they hold: fields the new type does not show are hidden, not deleted.`
              : 'No incident is of this type.'}
          </p>
          {saved.incidents > 0 && (
            <label className="flex flex-col gap-1" htmlFor="type-move-to">
              <span className="text-fg-muted">They become</span>
              <select
                id="type-move-to"
                value={moveTo}
                onChange={(event) => setMoveTo(event.target.value)}
                className={`${INPUT} cursor-pointer`}
              >
                {types
                  .filter((item) => item.id !== saved.id)
                  .map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.name}
                    </option>
                  ))}
              </select>
            </label>
          )}
        </div>
      </Modal>
    </div>
  )
}

export default function IncidentTypesSection() {
  const [types, setTypes] = useState(null)
  const [colours, setColours] = useState([])
  const [fields, setFields] = useState([])
  const [error, setError] = useState(null)
  const [openId, setOpenId] = useState(null)
  const [creating, setCreating] = useState(false)
  const [newName, setNewName] = useState('')
  const [busy, setBusy] = useState(false)

  // The incident page is drawn from the types: what changes here is read again for it.
  const { reload: reloadShared } = useFields()
  const load = useCallback(async () => {
    try {
      const [found, registry] = await Promise.all([api.get('/incident-types'), api.get('/fields')])
      setTypes(found.types)
      setColours(found.colours)
      setFields(registry.fields)
      reloadShared()
    } catch (failure) {
      setError(failure.message)
    }
  }, [reloadShared])
  useEffect(() => {
    load()
  }, [load])

  const naming = useUnsavedChanges(creating && Boolean(newName.trim()), { what: 'The new type of incident' })
  const create = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const made = await api.post('/incident-types', { name: newName.trim() })
      setCreating(false)
      setNewName('')
      await load()
      setOpenId(made.id)
    } catch (failure) {
      setError(failure.message)
      setCreating(false)
    } finally {
      setBusy(false)
    }
  }

  const open = types?.find((type) => type.id === openId) ?? null
  if (open) {
    return (
      <Builder
        key={open.id}
        type={open}
        fields={fields}
        colours={colours}
        types={types}
        onBack={() => setOpenId(null)}
        onSaved={(saved) => {
          setTypes(types.map((type) => (type.id === saved.id ? saved : type)))
          reloadShared()
        }}
        onDeleted={() => {
          setOpenId(null)
          load()
        }}
        onFieldCreated={(made) => setFields((current) => [...current, made])}
      />
    )
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-fg-muted">
        A type of incident says which fields its incidents have, where they are on the page and how one is closed. An
        incident that was given no type is <strong className="text-fg">Unclassified</strong>.
      </p>
      <div>
        <Button size="sm" icon={Plus} onClick={() => setCreating(true)}>
          New type
        </Button>
      </div>
      {error && (
        <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
          {error}
        </p>
      )}
      {!types && !error && (
        <p role="status" className="font-mono text-sm text-fg-muted">
          Loading the types…
        </p>
      )}
      {types && (
        <div className="overflow-x-auto border border-line">
          <table className="w-full min-w-[560px] border-collapse text-left text-sm">
            <caption className="sr-only">Incident types</caption>
            <thead className="bg-panel font-mono text-xs text-fg-muted">
              <tr>
                {['Type', 'Its own fields', 'Incidents'].map((heading) => (
                  <th key={heading} scope="col" className="border-b border-line px-3 py-1.5 font-normal">
                    {heading}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {types.map((type) => (
                <tr key={type.id} className="hover:bg-raised/40">
                  <th scope="row" className="border-b border-line-soft px-3 py-2 font-normal">
                    <button
                      type="button"
                      onClick={() => setOpenId(type.id)}
                      className="flex items-center gap-2 text-left font-medium text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    >
                      <Badge color={type.colour}>{type.name}</Badge>
                    </button>
                    {type.description && <span className="mt-1 block text-xs text-fg-muted">{type.description}</span>}
                  </th>
                  <td className="border-b border-line-soft px-3 py-2 font-mono text-xs text-fg-muted">
                    {type.fields.length || '—'}
                  </td>
                  <td className="border-b border-line-soft px-3 py-2 font-mono text-xs text-fg-muted">
                    {type.incidents || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Modal
        open={creating}
        onClose={() => naming.leave(() => setCreating(false))}
        title="New type"
        footer={
          <>
            <Button variant="secondary" onClick={() => setCreating(false)}>
              Cancel
            </Button>
            <Button type="submit" form="form-new-type" disabled={busy || !newName.trim()}>
              Create the type
            </Button>
          </>
        }
      >
        <form id="form-new-type" onSubmit={create} className="flex flex-col gap-2 text-sm">
          <label className="flex flex-col gap-1" htmlFor="new-type-name">
            <span className="text-fg-muted">Name</span>
            <input
              id="new-type-name"
              type="text"
              value={newName}
              maxLength={80}
              autoComplete="off"
              placeholder="Business e-mail compromise"
              onChange={(event) => setNewName(event.target.value)}
              className={INPUT}
            />
          </label>
          <p className="text-xs text-fg-muted">It starts with the key facts every incident has; add its own next.</p>
        </form>
      </Modal>
    </div>
  )
}
