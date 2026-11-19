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
