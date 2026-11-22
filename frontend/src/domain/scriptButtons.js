/*
 * Script buttons (6.2): a button on a page of an incident that runs a script.
 *
 * A widget of the kind `buttons` holds up to eight of
 *
 *   { label, background, color, script, args: { name: template } }
 *
 * The two colours are free. What is checked is whether the text can be read
 * on the button: the contrast ratio of WCAG, with a warning under 4.5 : 1
 * that stops nothing. An argument with a template is filled from the incident
 * when the button is pressed; one left empty is asked then. The server
 * renders the templates and runs the script (backend/app/buttons.py): what is
 * here is what the settings and the dialog of a press show.
 */

export const BUTTONS_MAX = 8
export const LABEL_MAX = 40
export const TEMPLATE_MAX = 2000
/** Under this ratio the text of a button is hard to read (WCAG AA, normal text). */
export const CONTRAST_MIN = 4.5
/** Above this many runs the dialog asks a second time before it starts them. */
export const WARN_RUNS = 50
export const DEFAULT_BACKGROUND = '#21262d'
export const DEFAULT_COLOR = '#e6edf3'

const HEX = /^#[0-9a-f]{6}$/i
const SHORT = /^#?([0-9a-f])([0-9a-f])([0-9a-f])$/i
const ARGUMENT = /^[a-z][a-z0-9_]{0,39}$/
const list = (value) => (Array.isArray(value) ? value : [])

/** A colour as it is kept: `#rrggbb` in lower case, or null for what is not a colour. `#abc` and `aabbcc` are read. */
export function hexColor(value) {
  const text = String(value ?? '').trim()
  if (HEX.test(text)) return text.toLowerCase()
  if (/^[0-9a-f]{6}$/i.test(text)) return `#${text.toLowerCase()}`
  const short = SHORT.exec(text)
  if (short) return `#${short[1]}${short[1]}${short[2]}${short[2]}${short[3]}${short[3]}`.toLowerCase()
  return null
}

/** The relative luminance of a colour (WCAG 2): 0 for black, 1 for white. */
export function luminance(hex) {
  const colour = hexColor(hex)
  if (!colour) return null
  const [red, green, blue] = [1, 3, 5].map((at) => {
    const channel = parseInt(colour.slice(at, at + 2), 16) / 255
    return channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4
  })
  return 0.2126 * red + 0.7152 * green + 0.0722 * blue
}

/** The contrast ratio of two colours, 1 to 21 (null when one is not a colour). */
export function contrast(first, second) {
  const a = luminance(first)
  const b = luminance(second)
  if (a === null || b === null) return null
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05)
}

/** "9.4 : 1", as the settings of a button show it. */
export const contrastText = (ratio) => (ratio === null ? '' : `${(Math.floor(ratio * 10) / 10).toFixed(1)} : 1`)

/** Whether the text of a button is hard to read on it. */
export const lowContrast = (button) => {
  const ratio = contrast(button?.background ?? DEFAULT_BACKGROUND, button?.color ?? DEFAULT_COLOR)
  return ratio !== null && ratio < CONTRAST_MIN
}

/** A button nobody set up yet. */
export const newButton = () => ({
  label: 'New button',
  background: DEFAULT_BACKGROUND,
  color: DEFAULT_COLOR,
  script: '',
  args: {},
})

/**
 * The buttons of a widget as they are kept: each with a text, two colours that
 * are colours (the default ones otherwise), a script and its templates, the
 * empty ones left out. Never throws.
 */
export function cleanButtons(buttons) {
  const out = []
  for (const raw of list(buttons).slice(0, BUTTONS_MAX)) {
    if (!raw || typeof raw !== 'object') continue
    const label = String(raw.label ?? '')
      .trim()
      .slice(0, LABEL_MAX)
    if (!label) continue
    const args = {}
    for (const [name, template] of Object.entries(raw.args && typeof raw.args === 'object' ? raw.args : {})) {
      const text = String(template ?? '').slice(0, TEMPLATE_MAX)
      if (ARGUMENT.test(name) && text.trim()) args[name] = text
    }
    out.push({
      label,
      background: hexColor(raw.background) ?? DEFAULT_BACKGROUND,
      color: hexColor(raw.color) ?? DEFAULT_COLOR,
      script: String(raw.script ?? ''),
      args,
    })
  }
  return out
}

/** The templates of a button for the arguments its script takes now: one that is gone is dropped. */
export function argsFor(button, script) {
  const names = new Set(list(script?.arguments).map((argument) => argument.name))
  return Object.fromEntries(Object.entries(button?.args ?? {}).filter(([name]) => names.has(name)))
}

/**
 * What "Pick a value" offers in the template of an argument (the tree of
 * automation/ExpressionInput.jsx): the fields of the type by their names,
 * then what an incident is called by.
 */
export function fieldTree(fields) {
  const own = list(fields)
    .filter((field) => field && field.name && field.type !== 'timer')
    .map((field) => ({ path: field.name, type: field.type ?? '', description: field.label ?? '' }))
  return [
    ...(own.length > 0 ? [{ name: 'fields', label: 'the fields of this type', fields: own }] : []),
    {
      name: 'incident',
      label: 'the incident',
      fields: [
        { path: 'incident.number', type: 'number', description: 'The number it is called by' },
        { path: 'incident.name', type: 'text', description: 'Its name' },
        { path: 'incident.host', type: 'text', description: 'The host it is about' },
        { path: 'incident.user', type: 'text', description: 'The account it is about' },
        { path: 'incident.severity', type: 'choice', description: 'Its severity' },
        { path: 'incident.owner', type: 'user', description: 'Who has it' },
        { path: 'incident.url', type: 'text', description: 'Its address in Nik' },
      ],
    },
  ]
}

/** A value of an argument as one line of the dialog. */
export function shownValue(value) {
  if (value === null || value === undefined) return ''
  if (typeof value === 'string') return value
  if (Array.isArray(value) && value.every((item) => typeof item !== 'object' || item === null)) return value.join(', ')
  return JSON.stringify(value)
}

/** Where a filled argument comes from: "from Sender address", "from Sender address · 3 values". */
export function sourceText(argument) {
  const from = argument?.source?.label ? `from ${argument.source.label}` : 'set in the button'
  return argument?.count > 1 ? `${from} · ${argument.count} values` : from
}

/** The text of the button that starts the runs: "Run", or "Run 3 times". */
export const runLabel = (runs) => (runs > 1 ? `Run ${runs} times` : 'Run')

/** "1.2 s", "340 ms", "2 min 5 s": how long a run took. */
export function tookText(ms) {
  if (!Number.isFinite(ms) || ms < 0) return ''
  if (ms < 1000) return `${Math.round(ms)} ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`
  return `${Math.floor(ms / 60_000)} min ${Math.round((ms % 60_000) / 1000)} s`
}

/**
 * The runs of a press as the dialog lists them: what the server started
 * (`{ index, item, runId }`) with where each is (`{ runId, status,
 * durationMs?, error? }`). A run the server did not answer for yet is running.
 */
export function mergeRuns(started, statuses) {
  const byId = new Map(list(statuses).map((status) => [status.runId, status]))
  return list(started).map((run) => {
    const found = byId.get(run.runId) ?? {}
    return {
      ...run,
      status: found.status ?? run.status ?? 'running',
      durationMs: found.durationMs ?? run.durationMs ?? null,
      error: found.error ?? run.error ?? null,
    }
  })
}

/** What the runs add up to: `{ running, done, failed }`. */
export function tally(runs) {
  const counts = { running: 0, done: 0, failed: 0 }
  for (const run of list(runs))
    counts[run.status === 'done' ? 'done' : run.status === 'failed' ? 'failed' : 'running'] += 1
  return counts
}

/** "Run the failed one again", or "Run the 3 failed ones again". */
export const againLabel = (failed) => (failed > 1 ? `Run the ${failed} failed ones again` : 'Run the failed one again')
