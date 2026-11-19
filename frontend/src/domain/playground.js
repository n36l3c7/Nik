/*
 * The Playground (GET /api/playground): the War Room without an incident, to
 * try a command or look something up. Its history is each person's own.
 */

export const PLAYGROUND_ROOT = '/playground'

export const isPlaygroundPath = (pathname) => /^\/playground(\/|$)/.test(String(pathname ?? '').split('?')[0])

/** The chips of the stream: there is no automation and no evidence where there is no incident. */
export const PLAYGROUND_FILTERS = [
  { id: 'all', label: 'All' },
  { id: 'notes', label: 'Notes' },
  { id: 'commands', label: 'Commands' },
]

/** The `/` lines the Playground takes: the others are about an incident. */
export const PLAYGROUND_SLASH = [{ name: '/note', hint: 'text', description: 'Write a note to yourself' }]

/**
 * The line that tries a command of a connector: `!<connector>-<command>`, its required arguments
 * left to fill, and the instance to use when one is given.
 */
export function tryLine(connectorId, command, instanceName = '') {
  const required = (command?.arguments ?? [])
    .filter((argument) => argument.required)
    .map((argument) => `${argument.name}=`)
  const using = instanceName ? `using=${/[\s"]/.test(instanceName) ? JSON.stringify(instanceName) : instanceName}` : ''
  return [`!${connectorId}-${command?.name ?? ''}`, ...required, using].filter(Boolean).join(' ')
}

const TRY_KEY = 'nik.playground.line'

/** Leave a line for the Playground to start with (it is opened next). */
export function leaveLine(line) {
  try {
    sessionStorage.setItem(TRY_KEY, String(line ?? ''))
  } catch {
    // No storage: the Playground opens with an empty line.
  }
}

/** The line that was left, once: asking again gives nothing. */
export function takeLine() {
  try {
    const line = sessionStorage.getItem(TRY_KEY) ?? ''
    sessionStorage.removeItem(TRY_KEY)
    return line
  } catch {
    return ''
  }
}
