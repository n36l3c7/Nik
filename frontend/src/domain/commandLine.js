/*
 * The command line of the War Room, as it is typed: what a line is, what
 * completes it, and the lines typed before.
 *
 *   plain text            a note
 *   /note /assign /close  a slash command
 *   !name arg=value …     a command (GET /api/automation/catalog → commands)
 *
 * The server reads the line again and is the one that decides; this only
 * helps to write it.
 */

export const SLASH = [
  { name: '/note', hint: 'text', description: 'Write a note' },
  { name: '/assign', hint: '@user', description: 'Give the incident to someone (alone: to nobody)' },
  { name: '/close', hint: '', description: 'Close the incident: opens the form of closing' },
]

const HISTORY_MAX = 50

/** 'note' | 'slash' | 'command' */
export function lineKind(text) {
  const line = String(text ?? '').trimStart()
  if (line.startsWith('!')) return 'command'
  if (line.startsWith('/')) return 'slash'
  return 'note'
}

/** The name being typed after `!` or `/`, and whether it is finished (a space follows). */
export function nameOf(text) {
  const line = String(text ?? '').trimStart()
  const found = /^([!/])(\S*)(\s?)/.exec(line)
  if (!found) return { sign: '', name: '', done: false }
  return { sign: found[1], name: found[2], done: found[3] !== '' }
}

/**
 * What can complete the line: while the name is typed, the commands that
 * start with it (those that hold it after them); none once it is finished.
 * `[{ value, label, description }]`, `value` being the line it becomes.
 */
export function completions(commands, text, limit = 8, slash = SLASH) {
  const { sign, name, done } = nameOf(text)
  if (!sign || done) return []
  const typed = name.toLowerCase()
  if (sign === '/') {
    return slash
      .filter((item) => item.name.slice(1).startsWith(typed))
      .map((item) => ({
        value: `${item.name} `,
        label: item.hint ? `${item.name} ${item.hint}` : item.name,
        description: item.description,
      }))
  }
  const all = Array.isArray(commands) ? commands : []
  const starts = all.filter((item) => item.name.toLowerCase().startsWith(typed))
  const holds = typed ? all.filter((item) => !starts.includes(item) && item.name.toLowerCase().includes(typed)) : []
  return [...starts, ...holds].slice(0, limit).map((item) => ({
    value: `!${item.name} `,
    label: `!${item.name}`,
    description: item.description ?? '',
    group: item.group ?? '',
  }))
}

/** The command a finished `!name` names, among those there are (null when none). */
export function commandOf(commands, text) {
  const { sign, name, done } = nameOf(text)
  if (sign !== '!' || !done) return null
  return (
    (Array.isArray(commands) ? commands : []).find((item) => item.name.toLowerCase() === name.toLowerCase()) ?? null
  )
}

/** The names already given on the line: `number=`, `using=`. */
function given(text) {
  return new Set([...String(text ?? '').matchAll(/(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=/g)].map((found) => found[1]))
}

/**
 * The arguments of the command being typed that are still to give, the
 * required ones first: `[{ name, type, required, description }]`.
 */
export function argumentHints(commands, text) {
  const command = commandOf(commands, text)
  if (!command) return []
  const used = given(text)
  const rest = (command.arguments ?? []).filter((argument) => !used.has(argument.name))
  const hints = [...rest.filter((argument) => argument.required), ...rest.filter((argument) => !argument.required)]
  if (command.needsConnection && !used.has('using')) {
    hints.push({ name: 'using', type: 'text', required: false, description: 'The connection to send through' })
  }
  return hints
}

/** The lines typed before, the newest last, without the same line twice in a row. */
export function remember(history, line) {
  const text = String(line ?? '').trim()
  const list = Array.isArray(history) ? history : []
  if (!text || list[list.length - 1] === text) return list
  return [...list, text].slice(-HISTORY_MAX)
}

/**
 * Walking the history with ↑ and ↓: `at` is the position (history.length is
 * "the line being written"). Returns the new position and the text to show.
 */
export function recall(history, at, by, draft = '') {
  const list = Array.isArray(history) ? history : []
  const next = Math.min(list.length, Math.max(0, at + by))
  return { at: next, text: next === list.length ? draft : list[next] }
}
