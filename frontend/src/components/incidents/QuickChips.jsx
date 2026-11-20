import { useState } from 'react'
import { ChevronDown } from 'lucide-react'
import { useContextMenu } from '../../context/ContextMenuContext.jsx'
import { CHIPS, addCondition, applyChip, chipChoices, chipCondition, otherFields } from '../../domain/incidentChips.js'
import { tagCondition, tagsInQuery, toggleTag, withoutTags } from '../../domain/incidentTags.js'
import { emptyRow, isComplete, opLabel, opsFor } from '../../domain/query/builder.js'
import { fieldCaption, fieldOf } from '../../domain/query/complete.js'
import { Button, Modal } from '../ui/index.js'

/*
 * The chips under the query of the incident list: "Add: Type, Severity,
 * Status, Owner, Opened, Tag, Field…". Each opens a menu and writes its
 * condition into the query; a chip whose field the query already has a
 * condition on shows it. They took the place of the status picker and of
 * "mine", and write the query the same way (domain/incidentChips.js).
 *
 * "Tag" lists the tags the incidents carry, with how many carry each. Where
 * another chip holds one condition, this one holds one for each tag chosen:
 * several tags keep the incidents that carry all of them, as every other
 * condition of the query narrows it (domain/incidentTags.js).
 */

// How many tags the menu of "Tag" lists: the most used. The others are typed (tag: completes them).
const TAGS_LISTED = 30

const CHIP =
  'inline-flex h-7 max-w-[16rem] items-center gap-1 border px-2.5 text-xs transition-colors ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const CONTROL =
  'h-8 min-w-0 border border-line bg-canvas px-2 font-mono text-xs text-fg ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/** A condition on any field of the incidents, built as a row of the query builder. */
function ConditionDialog({ schema, onAdd, onClose }) {
  const fields = otherFields(schema)
  const [row, setRow] = useState(() => emptyRow(fields[0]?.name ?? ''))
  const spec = fieldOf(schema, row.field)
  const kind = spec?.kind ?? 'text'
  const ops = opsFor(kind)
  const choices = kind === 'bool' ? ['true', 'false'] : (spec?.values ?? [])
  const noValue = row.op === 'empty' || row.op === 'filled'
  const set = (changes) => setRow((current) => ({ ...current, ...changes }))

  const value = (key, label) =>
    choices.length > 0 && row.op !== 'between' ? (
      <select
        aria-label={label}
        value={row[key]}
        onChange={(event) => set({ [key]: event.target.value })}
        className={`${CONTROL} flex-1`}
      >
        <option value="">choose…</option>
        {choices.map((choice) => (
          <option key={choice} value={choice}>
            {choice}
          </option>
        ))}
      </select>
    ) : (
      <input
        type="text"
        aria-label={label}
        value={row[key]}
        onChange={(event) => set({ [key]: event.target.value })}
        placeholder={kind === 'date' ? 'today, now-7d, 2026-11-10' : ''}
        autoComplete="off"
        spellCheck={false}
        className={`${CONTROL} flex-1 basis-32 placeholder:text-fg-subtle`}
      />
    )

  const submit = (event) => {
    event.preventDefault()
    if (!isComplete(row)) return
    onAdd(row)
    onClose()
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="Add a condition on a field"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="form-add-condition" disabled={!isComplete(row)}>
            Add to the query
          </Button>
        </>
      }
    >
      <form id="form-add-condition" onSubmit={submit} className="flex flex-col gap-3 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <select
            aria-label="Field"
            value={row.field}
            onChange={(event) => {
              const next = fieldOf(schema, event.target.value)
              const allowed = opsFor(next?.kind ?? 'text')
              setRow({ ...emptyRow(event.target.value), op: allowed.some((op) => op.id === row.op) ? row.op : '=' })
            }}
            className={`${CONTROL} max-w-[16rem]`}
          >
            {fields.map((field) => (
              <option key={field.name} value={field.name}>
                {fieldCaption(field)}
              </option>
            ))}
          </select>
          <select
            aria-label="Operator"
            value={row.op}
            onChange={(event) => set({ op: event.target.value })}
            className={`${CONTROL} max-w-[12rem]`}
          >
            {ops.map((op) => (
              <option key={op.id} value={op.id}>
                {opLabel(op, kind)}
              </option>
            ))}
          </select>
          {!noValue && value('value', row.op === 'between' ? 'From' : 'Value')}
          {row.op === 'between' && value('value2', 'To')}
        </div>
        {spec?.description && <p className="text-xs text-fg-muted">{spec.description}</p>}
        <p className="text-xs text-fg-muted">
          It takes the place of the condition the query has on this field, if it has one.
        </p>
      </form>
    </Modal>
  )
}

/**
 * @param {{
 *   query: string, onChange: (query: string) => void,
 *   schema: object | null,               // the incidents of GET /api/query/schema
 *   types: object[], assignees: string[], me: string,
 *   tags?: { tag: string, count: number }[],   // the tags in use, the most used first
 *   children?: import('react').ReactNode // what stands at the right end of the row
 * }} props
 */
export default function QuickChips({ query, onChange, schema, types, assignees, me, tags = [], children = null }) {
  const { openMenu } = useContextMenu()
  const [adding, setAdding] = useState(false)
  const asked = tagsInQuery(query, schema) ?? []
  const isAsked = (tag) => asked.some((item) => item.toLowerCase() === tag.toLowerCase())
  const askedText = asked.map((tag) => tagCondition(tag, schema)).join(' ')

  const openTags = (event) => {
    const box = event.currentTarget.getBoundingClientRect()
    // The tags the query asks for come first, so one nobody carries any more can still be taken out.
    const listed = [
      ...asked.filter((tag) => !tags.some((item) => item.tag.toLowerCase() === tag.toLowerCase())),
      ...tags.slice(0, TAGS_LISTED).map((item) => item.tag),
    ]
    const count = (tag) => tags.find((item) => item.tag === tag)?.count ?? 0
    openMenu(
      {
        clientX: box.left,
        clientY: box.bottom + 2,
        target: event.currentTarget,
        shiftKey: false,
        preventDefault: () => {},
        stopPropagation: () => {},
      },
      {
        title: 'Tag',
        items: [
          ...(listed.length === 0 ? [{ label: 'No incident has a tag yet', disabled: true, onSelect: () => {} }] : []),
          ...listed.map((tag) => ({
            label: `#${tag}`,
            hint: isAsked(tag) ? `${count(tag)} · in the query` : String(count(tag)),
            title: `${count(tag)} incident${count(tag) === 1 ? '' : 's'}`,
            onSelect: () => onChange(toggleTag(query, tag, schema)),
          })),
          ...(asked.length > 0
            ? [
                'separator',
                { label: 'Take the tags out of the query', onSelect: () => onChange(withoutTags(query, schema)) },
              ]
            : []),
        ],
      },
    )
  }

  // The menu of the app, opened under the chip instead of under the pointer: a key opens it too.
  const openUnder = (event, chip) => {
    const box = event.currentTarget.getBoundingClientRect()
    const held = chipCondition(query, chip.id, schema)
    const choices = chipChoices(chip.id, { types, assignees, me })
    openMenu(
      {
        clientX: box.left,
        clientY: box.bottom + 2,
        target: event.currentTarget,
        shiftKey: false,
        preventDefault: () => {},
        stopPropagation: () => {},
      },
      {
        title: chip.label,
        items: [
          ...choices.map((choice) => ({
            label: choice.label,
            hint: choice.condition === held ? 'in the query' : '',
            onSelect: () => onChange(applyChip(query, chip.id, choice.condition, schema)),
          })),
          ...(held
            ? [
                'separator',
                { label: 'Take it out of the query', onSelect: () => onChange(applyChip(query, chip.id, '', schema)) },
              ]
            : []),
        ],
      },
    )
  }

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <span className="text-xs text-fg-muted">Add:</span>
      {CHIPS.map((chip) => {
        const held = chipCondition(query, chip.id, schema)
        return (
          <button
            key={chip.id}
            type="button"
            aria-haspopup="menu"
            aria-label={held ? `${chip.label}: ${held}` : chip.label}
            title={held ? `The query has ${held}` : `Add a condition on ${chip.label.toLowerCase()}`}
            onClick={(event) => openUnder(event, chip)}
            className={`${CHIP} ${held ? 'border-accent text-accent-fg' : 'border-line bg-panel text-fg hover:bg-raised'}`}
          >
            <span className="truncate">{held ? <span className="font-mono">{held}</span> : chip.label}</span>
            <ChevronDown className="h-3 w-3 shrink-0" aria-hidden="true" />
          </button>
        )
      })}
      <button
        type="button"
        aria-haspopup="menu"
        aria-label={asked.length > 0 ? `Tag: ${askedText}` : 'Tag'}
        title={
          asked.length > 0
            ? `The query has ${askedText}`
            : 'Keep the incidents with a tag; several tags keep those with all of them'
        }
        onClick={openTags}
        className={`${CHIP} ${asked.length > 0 ? 'border-accent text-accent-fg' : 'border-line bg-panel text-fg hover:bg-raised'}`}
      >
        <span className="truncate">
          {asked.length > 0 ? (
            <span className="font-mono">
              {tagCondition(asked[0], schema)}
              {asked.length > 1 ? ` +${asked.length - 1}` : ''}
            </span>
          ) : (
            'Tag'
          )}
        </span>
        <ChevronDown className="h-3 w-3 shrink-0" aria-hidden="true" />
      </button>
      <button
        type="button"
        aria-haspopup="dialog"
        disabled={!schema}
        onClick={() => setAdding(true)}
        title="Add a condition on any field of the incidents"
        className={`${CHIP} border-line bg-panel text-fg hover:bg-raised disabled:opacity-50`}
      >
        Field…
      </button>
      {children && <span className="ml-auto flex flex-wrap items-center gap-1.5">{children}</span>}
      {adding && (
        <ConditionDialog
          schema={schema}
          onAdd={(row) => onChange(addCondition(query, row, schema))}
          onClose={() => setAdding(false)}
        />
      )}
    </div>
  )
}
