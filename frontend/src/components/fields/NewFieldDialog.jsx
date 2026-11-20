import { useState } from 'react'
import { api } from '../../services/api.js'
import { FIELD_TYPES, nameFromLabel, nameProblem } from '../../domain/fields.js'
import { Button, Modal } from '../ui/index.js'
import { useUnsavedChanges } from '../../lib/unsaved.js'

/*
 * "New field": a label, the machine name made from it, a type and what the
 * type needs (the choices of a choice, the columns of a table).
 *
 * The name and the type are for ever: playbooks, mappers and queries refer
 * to them. The dialog says so, and shows the name before it is taken.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const COLUMN_TYPES = ['text', 'number', 'bool', 'date', 'url']

/**
 * @param {{
 *   fields: object[],                       // the registry, to tell a name that is taken
 *   allTypes?: boolean,                     // the starting value of "on every type"
 *   onClose: () => void,
 *   onCreated: (field: object) => void,
 * }} props
 */
export default function NewFieldDialog({ fields, allTypes = false, onClose, onCreated }) {
  const [label, setLabel] = useState('')
  const [name, setName] = useState('')
  const [named, setNamed] = useState(false) // the name was typed by hand: it no longer follows the label
  const [type, setType] = useState('text')
  const [description, setDescription] = useState('')
  const [choices, setChoices] = useState('')
  const [columns, setColumns] = useState([{ label: '', type: 'text' }])
  const [everywhere, setEverywhere] = useState(allTypes)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const unsaved = useUnsavedChanges(
    Boolean(label.trim() || (named && name.trim()) || description.trim() || choices.trim()),
    { what: 'The new field' },
  )

  const machine = named ? name : nameFromLabel(label)
  const wrongName = machine ? nameProblem(machine, fields) : null
  const listed = choices
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
  const cols = columns.filter((column) => column.label.trim())
  const needs =
    type === 'choice' || type === 'multi_choice'
      ? listed.length === 0
        ? 'Write the choices, one per line'
        : null
      : type === 'list'
        ? cols.length === 0
          ? 'Give the table at least one column'
          : null
        : null
  const problem = !label.trim() ? 'Give the field a label' : (wrongName ?? needs)

  const submit = async (event) => {
    event.preventDefault()
    if (problem) return
    setBusy(true)
    setError(null)
    const options =
      type === 'choice' || type === 'multi_choice'
        ? { choices: listed }
        : type === 'list'
          ? {
              columns: cols.map((column) => ({
                name: nameFromLabel(column.label),
                label: column.label.trim(),
                type: column.type,
              })),
            }
          : {}
    try {
      const made = await api.post('/fields', {
        name: machine,
        label: label.trim(),
        description,
        type,
        options,
        allTypes: everywhere,
      })
      onCreated(made)
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
      title="New field"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="form-new-field" disabled={busy || Boolean(problem)}>
            Create the field
          </Button>
        </>
      }
    >
      <form id="form-new-field" onSubmit={submit} className="flex flex-col gap-4 text-sm">
        <label className="flex flex-col gap-1" htmlFor="field-label">
          <span className="text-fg-muted">Label</span>
          <input
            id="field-label"
            type="text"
            value={label}
            maxLength={80}
            autoComplete="off"
            placeholder="Business unit"
            onChange={(event) => setLabel(event.target.value)}
            className={INPUT}
          />
        </label>
        <label className="flex flex-col gap-1" htmlFor="field-name">
          <span className="text-fg-muted">Name</span>
          <input
            id="field-name"
            type="text"
            value={machine}
            maxLength={41}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => {
              setNamed(true)
              setName(event.target.value)
            }}
            className={`${INPUT} font-mono`}
          />
          <span className="text-xs text-fg-muted">
            What playbooks and queries write. It cannot be changed afterwards; the label can.
          </span>
          {machine && wrongName && <span className="text-xs text-high-fg">{wrongName}</span>}
        </label>
        <label className="flex flex-col gap-1" htmlFor="field-type">
          <span className="text-fg-muted">Type</span>
          <select
            id="field-type"
            value={type}
            onChange={(event) => setType(event.target.value)}
            className={`${INPUT} cursor-pointer`}
          >
            {Object.entries(FIELD_TYPES).map(([id, name_]) => (
              <option key={id} value={id}>
                {name_}
              </option>
            ))}
          </select>
          <span className="text-xs text-fg-muted">It cannot be changed afterwards either.</span>
        </label>
        {(type === 'choice' || type === 'multi_choice') && (
          <label className="flex flex-col gap-1" htmlFor="field-choices">
            <span className="text-fg-muted">Choices, one per line</span>
            <textarea
              id="field-choices"
              value={choices}
              rows={4}
              onChange={(event) => setChoices(event.target.value)}
              className={`${INPUT} resize-y`}
            />
            <span className="text-xs text-fg-muted">More can be added later.</span>
          </label>
        )}
        {type === 'list' && (
          <fieldset className="flex flex-col gap-2 border border-line-soft p-3">
            <legend className="px-1 font-mono text-[11px] uppercase tracking-wider text-fg-muted">Columns</legend>
            {columns.map((column, index) => (
              <div key={index} className="flex gap-2">
                <input
                  type="text"
                  aria-label={`Label of column ${index + 1}`}
                  value={column.label}
                  maxLength={80}
                  autoComplete="off"
                  placeholder="Account"
                  onChange={(event) =>
                    setColumns(
                      columns.map((item, at) => (at === index ? { ...item, label: event.target.value } : item)),
                    )
                  }
                  className={INPUT}
                />
                <select
                  aria-label={`Type of column ${index + 1}`}
                  value={column.type}
                  onChange={(event) =>
                    setColumns(columns.map((item, at) => (at === index ? { ...item, type: event.target.value } : item)))
                  }
                  className={`${INPUT} w-40 cursor-pointer`}
                >
                  {COLUMN_TYPES.map((id) => (
                    <option key={id} value={id}>
                      {FIELD_TYPES[id]}
                    </option>
                  ))}
                </select>
              </div>
            ))}
            <Button
              variant="secondary"
              size="xs"
              className="self-start"
              onClick={() => setColumns([...columns, { label: '', type: 'text' }])}
            >
              Add a column
            </Button>
          </fieldset>
        )}
        <label className="flex flex-col gap-1" htmlFor="field-description">
          <span className="text-fg-muted">What it is for (optional)</span>
          <input
            id="field-description"
            type="text"
            value={description}
            maxLength={1000}
            autoComplete="off"
            onChange={(event) => setDescription(event.target.value)}
            className={INPUT}
          />
        </label>
        <label className="flex items-start gap-2">
          <input
            type="checkbox"
            checked={everywhere}
            onChange={(event) => setEverywhere(event.target.checked)}
            className="mt-1 accent-accent"
          />
          <span>
            On every type of incident
            <span className="block text-xs text-fg-muted">
              Otherwise it is a field of the types that list it, and of no other.
            </span>
          </span>
        </label>
        {error && (
          <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-high-fg">
            {error}
          </p>
        )}
        {!error && problem && label.trim() && <p className="text-xs text-fg-muted">{problem}.</p>}
      </form>
    </Modal>
  )
}
