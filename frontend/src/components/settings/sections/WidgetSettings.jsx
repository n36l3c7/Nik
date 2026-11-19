import { useEffect, useMemo, useState } from 'react'
import { ArrowDown, ArrowUp, Plus, Trash2 } from 'lucide-react'
import { api } from '../../../services/api.js'
import { chartWidgets } from '../../../domain/linked.js'
import { fieldCaption } from '../../../domain/query/complete.js'
import {
  BUTTONS_MAX,
  CONTRAST_MIN,
  DEFAULT_BACKGROUND,
  DEFAULT_COLOR,
  LABEL_MAX,
  TEMPLATE_MAX,
  argsFor,
  contrast,
  contrastText,
  fieldTree,
  hexColor,
  newButton,
} from '../../../domain/scriptButtons.js'
import { Button } from '../../ui/index.js'
import ExpressionInput from '../../automation/ExpressionInput.jsx'

/*
 * ============================================================================
 * The settings of two widgets of a type's page: script buttons, a chart (6.2)
 * ============================================================================
 *
 * SCRIPT BUTTONS. A widget holds up to eight. Each has its text, the colour
 * of the button and of its text (free: the contrast is shown, with a warning
 * when the text would be hard to read, and the button is saved all the same),
 * the script it runs (one with a saved version) and, for every argument of
 * that script, a template: left empty, the argument is asked when the button
 * is pressed; with {{ a field }}, it is filled from the incident. A field
 * that holds several values runs the script once for each.
 *
 * CHART OF A DASHBOARD. A dashboard, one of its widgets, and the ONE field
 * of the incident its query is narrowed by.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const LABEL = 'flex flex-col gap-1 text-sm'
const CAPTION = 'font-mono text-[11px] uppercase tracking-wider text-fg-muted'

/** A colour: the picker of the browser, and its hex beside it, typed or pasted. */
function Colour({ id, label, value, fallback, onChange }) {
  const colour = hexColor(value)
  return (
    <label className={`${LABEL} min-w-0 flex-1`} htmlFor={id}>
      <span className="text-fg-muted">{label}</span>
      <span className="flex items-center gap-2">
        <input
          type="color"
          aria-label={`${label}, picked`}
          value={colour ?? fallback}
          onChange={(event) => onChange(event.target.value)}
          className="h-8 w-9 shrink-0 cursor-pointer border border-line bg-canvas p-0.5"
        />
        <input
          id={id}
          type="text"
          value={value}
          maxLength={7}
          autoComplete="off"
          spellCheck={false}
          aria-invalid={colour ? undefined : true}
          onChange={(event) => onChange(event.target.value)}
          className={`${INPUT} font-mono ${colour ? '' : 'border-high-line'}`}
        />
      </span>
      {!colour && <span className="text-xs text-high-fg">A colour is written #rrggbb.</span>}
    </label>
  )
}

/** The settings of one button. */
function ButtonSettings({ button, scripts, tree, onChange }) {
  const script = Array.isArray(scripts) ? (scripts.find((item) => item.name === button.script) ?? null) : null
  const ratio = contrast(button.background, button.color)
  const low = ratio !== null && ratio < CONTRAST_MIN
  const set = (changes) => onChange({ ...button, ...changes })
  return (
    <div className="flex flex-col gap-3 border border-line bg-panel p-3">
      <label className={LABEL} htmlFor="button-label">
        <span className="text-fg-muted">Text of the button</span>
        <input
          id="button-label"
          type="text"
          value={button.label}
          maxLength={LABEL_MAX}
          autoComplete="off"
          onChange={(event) => set({ label: event.target.value })}
          className={INPUT}
        />
      </label>
      <div className="flex flex-wrap items-start gap-3">
        <Colour
          id="button-background"
          label="Colour of the button"
          value={button.background}
          fallback={DEFAULT_BACKGROUND}
          onChange={(background) => set({ background })}
        />
        <Colour
          id="button-color"
          label="Colour of the text"
          value={button.color}
          fallback={DEFAULT_COLOR}
          onChange={(color) => set({ color })}
        />
        <div className={LABEL}>
          <span className="text-fg-muted">As drawn</span>
          <span
            role="img"
            aria-label={`The button as drawn: ${button.label || 'no text'}`}
            style={{
              backgroundColor: hexColor(button.background) ?? DEFAULT_BACKGROUND,
              color: hexColor(button.color) ?? DEFAULT_COLOR,
            }}
            className="inline-flex h-8 max-w-[14rem] items-center px-3 text-sm font-medium"
          >
            <span className="truncate">{button.label || 'no text'}</span>
          </span>
        </div>
      </div>
      {ratio !== null && (
        <p
          role={low ? 'alert' : 'status'}
          aria-label="Contrast of the button"
          className={`text-xs ${low ? 'border border-med-line bg-med-soft px-2 py-1 text-med-fg' : 'text-fg-muted'}`}
        >
          Contrast {contrastText(ratio)}.
          {low ? ` Under ${CONTRAST_MIN} : 1 the text is hard to read on the button. It is saved all the same.` : ''}
        </p>
      )}

      <label className={LABEL} htmlFor="button-script">
        <span className="text-fg-muted">Script</span>
        <select
          id="button-script"
          value={button.script}
          onChange={(event) => {
            const next = scripts.find((item) => item.name === event.target.value) ?? null
            // The templates of the arguments the new script takes too are kept.
            set({ script: event.target.value, args: argsFor(button, next) })
          }}
          disabled={!Array.isArray(scripts)}
          className={`${INPUT} cursor-pointer`}
        >
          <option value="">Choose a script…</option>
          {button.script && !script && <option value={button.script}>{button.script} · not in the library</option>}
          {(Array.isArray(scripts) ? scripts : []).map((item) => (
            <option key={item.name} value={item.name}>
              {item.name} · {item.arguments.length} {item.arguments.length === 1 ? 'argument' : 'arguments'}
            </option>
          ))}
        </select>
        {scripts === null && <span className="font-mono text-xs text-fg-muted">Loading the scripts…</span>}
        {scripts === false && (
          <span className="text-xs text-fg-muted">The scripts could not be read: the button keeps the one it has.</span>
        )}
        {Array.isArray(scripts) && scripts.length === 0 && (
          <span className="text-xs text-fg-muted">
            No script has a saved version yet: one is saved in Automations, Scripts.
          </span>
        )}
        {script?.description && <span className="text-xs text-fg-muted">{script.description}</span>}
      </label>

      {script && (
        <fieldset className="flex flex-col gap-3">
          <legend className={`${CAPTION} mb-2`}>Arguments of {script.name}</legend>
          {script.arguments.length === 0 && <p className="text-xs text-fg-muted">This script takes no argument.</p>}
          {script.arguments.map((argument) => {
            const id = `button-arg-${argument.name}`
            return (
              <div key={argument.name} className={LABEL}>
                <label htmlFor={id} className="text-fg-muted">
                  <span className="font-mono text-fg">{argument.name}</span>
                  {argument.required ? ' · required' : ''}
                  {argument.type && argument.type !== 'any' ? ` · ${argument.type}` : ''}
                </label>
                <ExpressionInput
                  id={id}
                  value={button.args?.[argument.name] ?? ''}
                  tree={tree}
                  braces
                  placeholder="left empty: asked when the button is pressed"
                  onChange={(text) => set({ args: { ...button.args, [argument.name]: text.slice(0, TEMPLATE_MAX) } })}
                />
                {argument.description && <span className="text-xs text-fg-muted">{argument.description}</span>}
              </div>
            )
          })}
          {script.arguments.length > 0 && (
            <p className="text-xs text-fg-muted">
              Typing <span className="font-mono">{'{{'}</span> offers the fields of this type. A field that holds
              several values runs the script once for each.
            </p>
          )}
        </fieldset>
      )}
    </div>
  )
}

/**
 * The buttons of a widget: the list, and the settings of the one that is chosen.
 * @param {{
 *   buttons: object[],
 *   fields: object[],                       // the fields of the type, offered in the templates
 *   onChange: (buttons: object[]) => void,
 * }} props
 */
export function ButtonsSettings({ buttons, fields, onChange }) {
  const [chosen, setChosen] = useState(0)
  const [scripts, setScripts] = useState(null) // null: not read yet; false: could not be read
  const tree = useMemo(() => fieldTree(fields), [fields])
  useEffect(() => {
    let alive = true
    api
      .get('/script-buttons/scripts')
      .then((found) => alive && setScripts(found.scripts))
      .catch(() => alive && setScripts(false))
    return () => {
      alive = false
    }
  }, [])

  const at = Math.min(chosen, buttons.length - 1)
  const move = (index, by) => {
    const next = [...buttons]
    next.splice(index + by, 0, ...next.splice(index, 1))
    onChange(next)
    setChosen(index + by)
  }
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <span className={`${CAPTION} flex-1`}>Buttons, {BUTTONS_MAX} at most</span>
        <Button
          variant="secondary"
          size="xs"
          icon={Plus}
          disabled={buttons.length >= BUTTONS_MAX}
          onClick={() => {
            onChange([...buttons, newButton()])
            setChosen(buttons.length)
          }}
        >
          Add a button
        </Button>
      </div>
      {buttons.length === 0 && <p className="text-sm text-fg-muted">No button yet.</p>}
      {buttons.length > 0 && (
        <ul aria-label="Buttons of the widget" className="flex flex-col gap-1">
          {buttons.map((button, index) => (
            <li
              key={index}
              className={`flex items-center gap-1 border px-2 py-1 ${index === at ? 'border-accent-strong bg-raised' : 'border-line-soft bg-canvas'}`}
            >
              <button
                type="button"
                aria-pressed={index === at}
                onClick={() => setChosen(index)}
                className="flex min-w-0 flex-1 items-center gap-2 text-left text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <span
                  aria-hidden="true"
                  style={{ backgroundColor: hexColor(button.background) ?? DEFAULT_BACKGROUND }}
                  className="h-3 w-3 shrink-0 border border-line"
                />
                <span className="min-w-0 flex-1 truncate">{button.label || 'no text'}</span>
                <span className="shrink-0 font-mono text-[10px] text-fg-muted">{button.script || 'no script'}</span>
              </button>
              <Button
                variant="ghost"
                size="xs"
                icon={ArrowUp}
                aria-label={`Move the button ${button.label} up`}
                disabled={index === 0}
                onClick={() => move(index, -1)}
              />
              <Button
                variant="ghost"
                size="xs"
                icon={ArrowDown}
                aria-label={`Move the button ${button.label} down`}
                disabled={index === buttons.length - 1}
                onClick={() => move(index, 1)}
              />
              <Button
                variant="ghost"
                size="xs"
                icon={Trash2}
                aria-label={`Remove the button ${button.label}`}
                onClick={() => {
                  onChange(buttons.filter((_, other) => other !== index))
                  setChosen(Math.max(0, at - (index <= at ? 1 : 0)))
                }}
              />
            </li>
          ))}
        </ul>
      )}
      {buttons[at] && (
        <ButtonSettings
          key={at}
          button={buttons[at]}
          scripts={scripts}
          tree={tree}
          onChange={(next) => onChange(buttons.map((button, index) => (index === at ? next : button)))}
        />
      )}
    </div>
  )
}

/** What is wrong with the buttons of a widget, as a sentence (null when they can be kept). */
export function buttonsProblem(buttons) {
  for (const button of buttons ?? []) {
    if (!String(button.label ?? '').trim()) return 'A button needs its text.'
    if (!hexColor(button.background) || !hexColor(button.color)) {
      return `The colours of “${button.label}” are written #rrggbb.`
    }
  }
  return null
}

/**
 * Which widget of which dashboard, and the field it is narrowed by.
 * @param {{ widget: object, onChange: (changes: object) => void }} props
 */
export function ChartSettings({ widget, onChange }) {
  const [boards, setBoards] = useState(null)
  const [board, setBoard] = useState(null) // the dashboard chosen, with its widgets
  const [schema, setSchema] = useState(null) // the fields of what the chosen widget counts
  const [error, setError] = useState(null)

  useEffect(() => {
    let alive = true
    api
      .get('/dashboards')
      .then((found) => alive && setBoards(found.dashboards))
      .catch((failure) => alive && setError(failure.message))
    return () => {
      alive = false
    }
  }, [])
  useEffect(() => {
    if (!widget.dashboard) return undefined
    let alive = true
    api
      .get(`/dashboards/${encodeURIComponent(widget.dashboard)}`)
      .then((found) => alive && setBoard(found))
      .catch(() => alive && setBoard({ id: widget.dashboard, widgets: [], gone: true }))
    return () => {
      alive = false
    }
  }, [widget.dashboard])

  const shown = board && board.id === widget.dashboard ? board : null
  const widgets = chartWidgets(shown)
  const chosen = widgets.find((item) => item.id === widget.widget) ?? null
  const entity = chosen?.entity ?? ''
  useEffect(() => {
    if (!entity) return undefined
    let alive = true
    api
      .get(`/query/schema?entity=${encodeURIComponent(entity)}`)
      .then((found) => alive && setSchema({ entity, fields: found.entities?.[0]?.fields ?? [] }))
      .catch(() => alive && setSchema({ entity, fields: [] }))
    return () => {
      alive = false
    }
  }, [entity])
  const fields = schema && schema.entity === entity ? schema.fields : []
  const personal = (boards ?? []).find((item) => item.id === widget.dashboard && !item.builtin && !item.shared)

  return (
    <div className="flex flex-col gap-3">
      <label className={LABEL} htmlFor="chart-dashboard">
        <span className="text-fg-muted">Dashboard</span>
        <select
          id="chart-dashboard"
          value={widget.dashboard ?? ''}
          onChange={(event) => onChange({ dashboard: event.target.value, widget: '', field: '' })}
          className={`${INPUT} cursor-pointer`}
        >
          <option value="">Choose a dashboard…</option>
          {(boards ?? []).map((item) => (
            <option key={item.id} value={item.id}>
              {item.name}
              {item.builtin ? ' · shipped with Nik' : item.shared ? ' · shared' : ' · only yours'}
            </option>
          ))}
        </select>
        {personal && (
          <span className="text-xs text-med-fg">
            This dashboard is only yours: nobody else will see its chart on an incident until it is shared.
          </span>
        )}
        {shown?.gone && <span className="text-xs text-high-fg">This dashboard is gone, or is no longer shared.</span>}
      </label>
      <label className={LABEL} htmlFor="chart-widget">
        <span className="text-fg-muted">Widget of the dashboard</span>
        <select
          id="chart-widget"
          value={widget.widget ?? ''}
          disabled={!shown}
          onChange={(event) => onChange({ widget: event.target.value, field: '' })}
          className={`${INPUT} cursor-pointer`}
        >
          <option value="">Choose a widget…</option>
          {widgets.map((item) => (
            <option key={item.id} value={item.id}>
              {item.title || item.type} · {item.entity}
            </option>
          ))}
        </select>
        <span className="text-xs text-fg-muted">The widgets that ask a query: a text has nothing to narrow.</span>
      </label>
      <label className={LABEL} htmlFor="chart-field">
        <span className="text-fg-muted">Narrowed by the incident’s</span>
        <select
          id="chart-field"
          value={widget.field ?? ''}
          disabled={!chosen}
          onChange={(event) => onChange({ field: event.target.value })}
          className={`${INPUT} cursor-pointer`}
        >
          <option value="">Choose a field…</option>
          {fields.map((field) => (
            <option key={field.name} value={field.name} title={field.description}>
              {fieldCaption(field)}
            </option>
          ))}
        </select>
        <span className="text-xs text-fg-muted">
          The query of the widget gets this field with what the incident holds for it: the chart counts what this
          incident shares with the others. An incident that holds nothing for it shows no chart. Every field a query can
          ask is here, those made in Settings too.
        </span>
      </label>
      {error && (
        <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
          {error}
        </p>
      )}
    </div>
  )
}
