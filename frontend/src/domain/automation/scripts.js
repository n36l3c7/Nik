/*
 * Scripts as their editor needs them: the draft being written, what makes
 * it saveable, and what changed between two versions of the code. The
 * server's rules are in backend/app/automation/scripts.py, and it decides.
 *
 * A draft: { code, arguments: [{ name, type, required, description }],
 *            outputs: [{ name, type, description }],
 *            test: { args, expect? } }
 */

export const NAME_RE = /^[A-Z][A-Za-z0-9]{2,48}$/
export const FIELD_RE = /^[a-z][a-z0-9_]{0,39}$/
export const TYPES = ['text', 'number', 'bool', 'list', 'object', 'any']
export const MAX_FIELDS = 30

export const EMPTY_DRAFT = { code: '', arguments: [], outputs: [], test: { args: {} } }

/** Why a name cannot be a script's, or null. */
export function nameProblem(name) {
  const text = String(name ?? '').trim()
  if (!text) return 'A name is needed'
  if (!NAME_RE.test(text)) return 'A capital letter, then letters and digits only: GroupByField (3 to 49 characters)'
  return null
}

/** What the editor starts from: the stored draft, else the current version, else nothing. */
export function draftOf(script) {
  const source = script?.draft ?? script?.current ?? EMPTY_DRAFT
  return {
    code: typeof source.code === 'string' ? source.code : '',
    arguments: Array.isArray(source.arguments) ? source.arguments : [],
    outputs: Array.isArray(source.outputs) ? source.outputs : [],
    test: {
      args: source.test?.args && typeof source.test.args === 'object' ? source.test.args : {},
      ...(source.test && 'expect' in source.test ? { expect: source.test.expect } : {}),
    },
  }
}

const shape = (draft) =>
  JSON.stringify({
    code: draft?.code ?? '',
    arguments: (draft?.arguments ?? []).map((field) => [
      field.name,
      field.type ?? 'any',
      Boolean(field.required),
      field.description ?? '',
    ]),
    outputs: (draft?.outputs ?? []).map((field) => [field.name, field.type ?? 'any', field.description ?? '']),
    test: draft?.test ?? {},
  })

/** True when two drafts are the same script (what decides "draft changed"). */
export const sameDraft = (a, b) => shape(a) === shape(b)

/** What is wrong with the arguments or the outputs: `[{ index, message }]`. */
export function fieldProblems(fields) {
  const problems = []
  const seen = new Set()
  if ((fields ?? []).length > MAX_FIELDS) problems.push({ index: MAX_FIELDS, message: `${MAX_FIELDS} at most` })
  ;(fields ?? []).forEach((field, index) => {
    const name = String(field?.name ?? '')
    if (!FIELD_RE.test(name)) problems.push({ index, message: 'A lower-case letter, then letters, digits or _' })
    else if (seen.has(name)) problems.push({ index, message: `Two are called "${name}"` })
    seen.add(name)
  })
  return problems
}

/** JSON typed in a box: `{ value }`, or `{ error }` with a sentence. Empty text is `fallback`. */
export function parseJson(text, fallback = undefined) {
  const source = String(text ?? '').trim()
  if (source === '') return { value: fallback }
  try {
    return { value: JSON.parse(source) }
  } catch (failure) {
    return { error: `Not JSON: ${failure.message}` }
  }
}

/** What keeps a draft from being tested or saved, as sentences; [] when nothing does. */
export function draftProblems(draft) {
  const problems = []
  if (!String(draft?.code ?? '').trim()) problems.push('The script has no code')
  else if (!/^\s*def\s+main\s*\(/m.test(draft.code)) problems.push('The code needs a function: def main(args)')
  if (fieldProblems(draft?.arguments).length) problems.push('An argument has no valid name')
  if (fieldProblems(draft?.outputs).length) problems.push('An output has no valid name')
  if (!draft?.test?.args || typeof draft.test.args !== 'object' || Array.isArray(draft.test.args)) {
    problems.push('The arguments of the test are an object: {"name": value}')
  }
  return problems
}

// --------------------------------------------------------------------------- //
// What changed between two versions of the code                               //
// --------------------------------------------------------------------------- //
const DIFF_MAX_LINES = 2000

/**
 * The lines of `after` against those of `before`: `[{ kind, text }]` with
 * kind 'same', 'add' or 'remove', in reading order. Above a size it stops
 * comparing and gives both whole (removed, then added).
 */
export function lineDiff(before, after) {
  const a = String(before ?? '').split('\n')
  const b = String(after ?? '').split('\n')
  if (a.length > DIFF_MAX_LINES || b.length > DIFF_MAX_LINES) {
    return [...a.map((text) => ({ kind: 'remove', text })), ...b.map((text) => ({ kind: 'add', text }))]
  }
  // Longest common subsequence, by table.
  const rows = a.length + 1
  const cols = b.length + 1
  const table = new Uint16Array(rows * cols)
  for (let i = a.length - 1; i >= 0; i -= 1) {
    for (let j = b.length - 1; j >= 0; j -= 1) {
      table[i * cols + j] =
        a[i] === b[j] ? table[(i + 1) * cols + j + 1] + 1 : Math.max(table[(i + 1) * cols + j], table[i * cols + j + 1])
    }
  }
  const out = []
  let i = 0
  let j = 0
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      out.push({ kind: 'same', text: a[i] })
      i += 1
      j += 1
    } else if (table[(i + 1) * cols + j] >= table[i * cols + j + 1]) {
      out.push({ kind: 'remove', text: a[i] })
      i += 1
    } else {
      out.push({ kind: 'add', text: b[j] })
      j += 1
    }
  }
  while (i < a.length) out.push({ kind: 'remove', text: a[i++] })
  while (j < b.length) out.push({ kind: 'add', text: b[j++] })
  return out
}

/** How many lines a diff adds and removes. */
export function diffCounts(diff) {
  return {
    added: diff.filter((line) => line.kind === 'add').length,
    removed: diff.filter((line) => line.kind === 'remove').length,
  }
}
