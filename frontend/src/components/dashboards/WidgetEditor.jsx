import { useEffect, useId, useState } from 'react'
import {
  BUCKETS,
  ENTITIES,
  FUNCTIONS,
  TYPES,
  asks,
  entityOf,
  groupText,
  measureText,
  newWidget,
  parseGroup,
  parseMeasure,
  typeOf,
} from '../../domain/dashboards.js'
import { useQuerySchema } from '../../services/querySchema.js'
import { Button, Modal } from '../ui/index.js'
import QueryInput from '../ui/QueryInput.jsx'
import Widget from './Widget.jsx'
import { useUnsavedChanges } from '../../lib/unsaved.js'

/*
 * ============================================================================
 * WIDGET EDITOR — what a widget asks, with its answer beside it
 * ============================================================================
 *
 * On the left: the type, what it is asked of (an entity and a query, built
 * or written, as everywhere else), how the answer is grouped and measured,
 * and what the type itself needs. On the right the widget as it will be,
 * with the real data of the person editing. The server checks it again when
 * the dashboard is saved.
 */

const CONTROL =
  'h-8 min-w-0 border border-line bg-canvas px-2 text-sm text-fg ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50'
const FIELD = `${CONTROL} w-full`
const LABEL = 'mb-1 block text-xs font-medium text-fg-muted'

function Field({ label, hint = null, children }) {
  const id = useId()
  return (
    <div>
      <label htmlFor={id} className={LABEL}>
        {label}
      </label>
      {children(id)}
      {hint && <p className="mt-1 text-xs text-fg-muted">{hint}</p>}
    </div>
  )
}

function Check({ checked, onChange, children }) {
  return (
    <label className="flex items-center gap-2 text-sm text-fg">
      <input
        type="checkbox"
        checked={Boolean(checked)}
        onChange={(event) => onChange(event.target.checked)}
        className="h-4 w-4 accent-[var(--color-accent)]"
      />
      {children}
    </label>
  )
}

/** One group: a field, and for a date the stretch of time it is grouped by. */
function GroupPicker({ id, value, fields, optional, onChange }) {
  const { field, bucket } = parseGroup(value)
  const spec = fields.find((item) => item.name === field)
  return (
    <div className="flex gap-2">
      <select
        id={id}
        value={field}
        onChange={(event) => {
          const next = fields.find((item) => item.name === event.target.value)
          onChange(next ? groupText({ field: next.name, bucket: next.kind === 'date' ? bucket || 'day' : '' }) : '')
        }}
        className={`${CONTROL} flex-1`}
      >
        {optional && <option value="">(none)</option>}
        {!spec && field && <option value={field}>{field}</option>}
        {fields.map((item) => (
          <option key={item.name} value={item.name}>
            {item.name}
          </option>
        ))}
      </select>
      {spec?.kind === 'date' && (
        <select
          aria-label="Grouped by"
          value={bucket || 'day'}
          onChange={(event) => onChange(groupText({ field, bucket: event.target.value }))}
          className={`${CONTROL} w-28 shrink-0`}
        >
          {BUCKETS.map((name) => (
            <option key={name} value={name}>
              by {name}
            </option>
          ))}
        </select>
      )}
    </div>
  )
}

/**
 * @param {{
 *   widget: object,                       // the widget as it is on the dashboard
 *   board: object,                        // the dashboard (its filter narrows the preview too)
 *   range: string,
 *   onSave: (widget: object) => void,
 *   onClose: () => void,
 * }} props
 */
export default function WidgetEditor({ widget, board, range, onSave, onClose }) {
  const [draft, setDraft] = useState(widget)
  // The preview follows the form a moment later, so that typing a query does not ask at every key.
  const [shown, setShown] = useState(widget)
  useEffect(() => {
    const timer = setTimeout(() => setShown(draft), 400)
    return () => clearTimeout(timer)
  }, [draft])

  const meta = typeOf(draft.type)
  const asking = asks(draft)
  // "Done" puts the widget on the dashboard being edited; closing any other way gives the changes up.
  const unsaved = useUnsavedChanges(JSON.stringify(draft) !== JSON.stringify(widget), {
    what: 'The widget',
    name: draft.title,
  })
  const close = () => unsaved.leave(onClose)
  const schema = useQuerySchema(draft.entity ?? 'incidents')
  const fields = schema?.fields ?? []
  const dates = fields.filter((field) => field.kind === 'date')
  const numbers = fields.filter((field) => field.kind === 'number')
  const measure = parseMeasure(draft.measure)
  const options = draft.options ?? {}
  const set = (patch) => setDraft((old) => ({ ...old, ...patch }))
  const setOption = (name, value) =>
    setDraft((old) => {
      const next = { ...(old.options ?? {}) }
      if (value === '' || value === false || value == null) delete next[name]
      else next[name] = value
      return { ...old, options: next }
    })

  const changeType = (type) => {
    const fresh = newWidget(type, draft.id)
    const next = typeOf(type)
    if (!next.groups) return setDraft({ ...fresh, title: draft.title, x: draft.x, y: draft.y, w: draft.w, h: draft.h })
    // What still makes sense is kept: the entity, the query, as many groups as the new type takes.
    const kept = asking ? (draft.groupBy ?? []).slice(0, next.groups[1]) : []
    const groupBy = kept.length >= next.groups[0] ? kept : fresh.groupBy
    setDraft({
      ...fresh,
      title: draft.title,
      x: draft.x,
      y: draft.y,
      w: draft.w,
      h: draft.h,
      entity: asking ? draft.entity : fresh.entity,
      query: asking ? draft.query : '',
      groupBy: type === 'trend' && !parseGroup(groupBy[0]).bucket ? fresh.groupBy : groupBy,
      measure: asking && type !== 'table' && type !== 'duration' ? draft.measure : fresh.measure,
    })
  }
  const changeEntity = (entity) => {
    const fresh = newWidget(draft.type, draft.id)
    const time = entityOf(entity)?.time ?? 'created'
    const groupBy = (fresh.groupBy ?? []).map((text) => (parseGroup(text).bucket ? `${time}@day` : text))
    set({
      entity,
      query: '',
      measure: 'count',
      groupBy: entity === 'incidents' ? fresh.groupBy : groupBy.map((text) => (text === 'severity' ? 'status' : text)),
      options:
        draft.type === 'table' ? { columns: [] } : draft.type === 'gauge' ? { target: options.target ?? 10 } : {},
    })
  }
  const setGroup = (index, text) => {
    const next = [...(draft.groupBy ?? [])]
    if (text) next[index] = text
    else next.splice(index, 1)
    set({ groupBy: next.filter(Boolean) })
  }
  const setMeasure = (patch) => set({ measure: measureText({ ...measure, ...patch }) })
  const measureOf = measure.fn === 'count' ? '' : measure.from ? '\u0000between' : measure.field

  return (
    <Modal
      open
      onClose={close}
      title={widget.title ? `Edit "${widget.title}"` : 'Edit the widget'}
      maxWidth="max-w-5xl"
      tall
      footer={
        <>
          <Button variant="secondary" onClick={close}>
            Cancel
          </Button>
          <Button onClick={() => onSave(draft)}>Done</Button>
        </>
      }
    >
      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <div className="space-y-4">
          <Field label="Title">
            {(id) => (
              <input
                id={id}
                type="text"
                maxLength={120}
                value={draft.title ?? ''}
                onChange={(event) => set({ title: event.target.value })}
                className={FIELD}
              />
            )}
          </Field>
          <Field label="Type" hint={meta?.hint}>
            {(id) => (
              <select id={id} value={draft.type} onChange={(event) => changeType(event.target.value)} className={FIELD}>
                {TYPES.map((type) => (
                  <option key={type.id} value={type.id}>
                    {type.label}
                  </option>
                ))}
              </select>
            )}
          </Field>

          {draft.type === 'text' && (
            <Field label="Text" hint="Markdown: headings, lists, links, bold and code.">
              {(id) => (
                <textarea
                  id={id}
                  rows={8}
                  maxLength={5000}
                  value={options.text ?? ''}
                  onChange={(event) => setOption('text', event.target.value)}
                  className={`${FIELD} h-auto py-1.5 font-mono text-xs`}
                />
              )}
            </Field>
          )}

          {asking && (
            <>
              <Field label="Of" hint={schema === null ? 'Its fields are listed for who may query it.' : null}>
                {(id) => (
                  <select
                    id={id}
                    value={draft.entity}
                    onChange={(event) => changeEntity(event.target.value)}
                    className={FIELD}
                  >
                    {ENTITIES.map((entity) => (
                      <option key={entity.id} value={entity.id}>
                        {entity.label}
                      </option>
                    ))}
                  </select>
                )}
              </Field>
              <div>
                <span className={LABEL}>Which ones</span>
                <QueryInput
                  entity={draft.entity}
                  value={draft.query ?? ''}
                  onChange={(query) => set({ query })}
                  label="The query of the widget"
                  placeholder="All of them"
                />
              </div>

              {meta.groups[1] > 0 &&
                Array.from({ length: meta.groups[1] }, (_, index) => (
                  <Field
                    key={index}
                    label={index === 0 ? (meta.groups[1] > 1 ? 'Grouped by' : 'For each') : 'Split by'}
                  >
                    {(id) => (
                      <GroupPicker
                        id={id}
                        value={draft.groupBy?.[index] ?? ''}
                        fields={draft.type === 'trend' && index === 0 ? dates : fields}
                        optional={index >= meta.groups[0]}
                        onChange={(text) => setGroup(index, text)}
                      />
                    )}
                  </Field>
                ))}

              {draft.type !== 'table' && (
                <div className="grid grid-cols-2 gap-2">
                  <Field label="Measure">
                    {(id) => (
                      <select
                        id={id}
                        value={measure.fn}
                        onChange={(event) => {
                          const fn = event.target.value
                          if (fn === 'count') return set({ measure: 'count' })
                          const first = dates[0]?.name ?? 'created'
                          const keep = measure.from || measure.field
                          return keep ? setMeasure({ fn }) : setMeasure({ fn, from: first, to: 'now' })
                        }}
                        className={FIELD}
                      >
                        {FUNCTIONS.map((fn) => (
                          <option key={fn.id} value={fn.id}>
                            {fn.label}
                          </option>
                        ))}
                      </select>
                    )}
                  </Field>
                  {measure.fn !== 'count' && (
                    <Field label="Of">
                      {(id) => (
                        <select
                          id={id}
                          value={measureOf}
                          onChange={(event) =>
                            event.target.value === '\u0000between'
                              ? setMeasure({ field: '', from: dates[0]?.name ?? 'created', to: 'now' })
                              : setMeasure({ field: event.target.value, from: '', to: '' })
                          }
                          className={FIELD}
                        >
                          <option value={'\u0000between'}>the time between two dates</option>
                          {numbers.map((field) => (
                            <option key={field.name} value={field.name}>
                              {field.name}
                            </option>
                          ))}
                        </select>
                      )}
                    </Field>
                  )}
                  {measure.fn !== 'count' && measure.from && (
                    <>
                      <Field label="From">
                        {(id) => (
                          <select
                            id={id}
                            value={measure.from}
                            onChange={(event) => setMeasure({ from: event.target.value })}
                            className={FIELD}
                          >
                            {dates.map((field) => (
                              <option key={field.name} value={field.name}>
                                {field.name}
                              </option>
                            ))}
                          </select>
                        )}
                      </Field>
                      <Field label="To">
                        {(id) => (
                          <select
                            id={id}
                            value={measure.to || 'now'}
                            onChange={(event) => setMeasure({ to: event.target.value })}
                            className={FIELD}
                          >
                            <option value="now">now (an age)</option>
                            {dates.map((field) => (
                              <option key={field.name} value={field.name}>
                                {field.name}
                              </option>
                            ))}
                          </select>
                        )}
                      </Field>
                    </>
                  )}
                </div>
              )}

              {draft.type === 'gauge' && (
                <div className="grid grid-cols-2 items-end gap-2">
                  <Field label="Target" hint={measure.from ? 'In seconds.' : null}>
                    {(id) => (
                      <input
                        id={id}
                        type="number"
                        min="0"
                        step="any"
                        value={options.target ?? ''}
                        onChange={(event) =>
                          setOption('target', event.target.value === '' ? '' : Number(event.target.value))
                        }
                        className={FIELD}
                      />
                    )}
                  </Field>
                  <Check checked={options.lowerIsBetter} onChange={(on) => setOption('lowerIsBetter', on)}>
                    Lower is better
                  </Check>
                </div>
              )}

              {draft.type === 'table' && (
                <fieldset>
                  <legend className={LABEL}>Columns</legend>
                  <div className="flex max-h-28 flex-wrap gap-x-4 gap-y-1 overflow-y-auto border border-line p-2">
                    {fields.map((field) => (
                      <Check
                        key={field.name}
                        checked={(options.columns ?? []).includes(field.name)}
                        onChange={(on) =>
                          setOption(
                            'columns',
                            on
                              ? [...(options.columns ?? []), field.name].slice(0, 12)
                              : (options.columns ?? []).filter((name) => name !== field.name),
                          )
                        }
                      >
                        {field.name}
                      </Check>
                    ))}
                  </div>
                </fieldset>
              )}

              <div className="grid grid-cols-2 gap-2">
                <Field label="Time field" hint="What the time range of the dashboard is counted on.">
                  {(id) => (
                    <select
                      id={id}
                      value={options.timeField ?? ''}
                      onChange={(event) => setOption('timeField', event.target.value)}
                      className={FIELD}
                    >
                      <option value="">{entityOf(draft.entity)?.time ?? 'created'} (the usual)</option>
                      {dates.map((field) => (
                        <option key={field.name} value={field.name}>
                          {field.name}
                        </option>
                      ))}
                    </select>
                  )}
                </Field>
                {['bar', 'pie', 'top', 'table', 'stacked_bar'].includes(draft.type) && (
                  <Field label="How many">
                    {(id) => (
                      <input
                        id={id}
                        type="number"
                        min="1"
                        max={draft.type === 'table' ? 100 : 50}
                        value={options.limit ?? 10}
                        onChange={(event) => setOption('limit', Number(event.target.value) || 10)}
                        className={FIELD}
                      />
                    )}
                  </Field>
                )}
                {draft.type !== 'table' && (
                  <Field label="Written as">
                    {(id) => (
                      <select
                        id={id}
                        value={options.format ?? ''}
                        onChange={(event) => setOption('format', event.target.value)}
                        className={FIELD}
                      >
                        <option value="">As it comes</option>
                        <option value="number">A number</option>
                        <option value="duration">A duration (from seconds)</option>
                        <option value="bytes">A size (from bytes)</option>
                        <option value="percent">A percentage</option>
                      </select>
                    )}
                  </Field>
                )}
              </div>
              <div className="space-y-1.5">
                {draft.type === 'number' && (
                  <Check checked={options.compare} onChange={(on) => setOption('compare', on)}>
                    Show the change against the period before
                  </Check>
                )}
                <Check checked={options.ignoreRange} onChange={(on) => setOption('ignoreRange', on)}>
                  Ignore the time range of the dashboard
                </Check>
                <Check checked={options.ignoreFilter} onChange={(on) => setOption('ignoreFilter', on)}>
                  Ignore the filter of the dashboard
                </Check>
              </div>
            </>
          )}
        </div>

        <div className="flex min-h-0 flex-col">
          <span className={LABEL}>As it will be, with your data</span>
          <section aria-label="Preview" className="flex h-80 flex-col border border-line bg-panel">
            <h3 className="flex h-8 shrink-0 items-center truncate px-3 text-xs font-semibold text-fg">
              {shown.title || meta?.label}
            </h3>
            <div className="min-h-0 flex-1 px-3 pb-3">
              <Widget widget={shown} board={board} range={range} />
            </div>
          </section>
          <p className="mt-2 text-xs text-fg-muted">
            A widget asks as whoever looks at it: on a shared dashboard each person sees what their own roles let them
            read.
          </p>
        </div>
      </div>
    </Modal>
  )
}
