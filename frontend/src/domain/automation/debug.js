/*
 * The debugger, as the page of a run reasons about it: where a debug run is
 * stopped, the arguments a person types for a node, the breakpoints. The
 * server decides what a debug run does (app/automation/debugger.py).
 */

/** The steps a debug run is stopped at, with their nodes: `[{ step, node }]`. */
export function stoppedAt(run) {
  const steps = run?.steps ?? []
  return (run?.debug?.at ?? []).map((where) => steps.find((step) => step.id === where.step)).filter(Boolean)
}

/** The arguments a node would be given, as the text a person edits ('' when the node takes none). */
export function argsText(step) {
  const args = step?.input?.args
  if (!args || typeof args !== 'object' || Array.isArray(args) || !Object.keys(args).length) return ''
  return JSON.stringify(args, null, 2)
}

/**
 * What a person typed as arguments: `{ value, error }`. Empty text is no change (value null); anything
 * else must be a JSON object.
 */
export function parseObject(text, what = 'The arguments') {
  const typed = String(text ?? '').trim()
  if (!typed) return { value: null, error: null }
  try {
    const value = JSON.parse(typed)
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      return { value: null, error: `${what} are an object: { "name": value }` }
    }
    return { value, error: null }
  } catch (failure) {
    return { value: null, error: `Not valid JSON: ${failure.message}` }
  }
}

/** Any JSON value a person typed (the output of a node): `{ value, error, empty }`. */
export function parseValue(text) {
  const typed = String(text ?? '').trim()
  if (!typed) return { value: undefined, error: null, empty: true }
  try {
    return { value: JSON.parse(typed), error: null, empty: false }
  } catch (failure) {
    return { value: undefined, error: `Not valid JSON: ${failure.message}`, empty: false }
  }
}

/** Only what differs from what the node would be given: the overrides to send (null when nothing differs). */
export function overridesOf(step, typed) {
  const given = step?.input?.args ?? {}
  if (!typed) return null
  const changed = Object.fromEntries(
    Object.entries(typed).filter(([name, value]) => JSON.stringify(given[name]) !== JSON.stringify(value)),
  )
  return Object.keys(changed).length ? changed : null
}

/** The breakpoints with one node added or taken off. */
export function toggleBreakpoint(breakpoints, nodeId) {
  const held = breakpoints ?? []
  return held.includes(nodeId) ? held.filter((id) => id !== nodeId) : [...held, nodeId]
}

/** A node the debugger can stop before (never the trigger). */
export const canBreak = (node) => Boolean(node) && node.kind !== 'trigger'

/** A step whose node can be run again while the run is not over. */
export const canRerun = (step, node) =>
  Boolean(step && node) &&
  ['done', 'failed', 'skipped'].includes(step.status) &&
  !['trigger', 'for_each', 'end'].includes(node.kind)

/** Where a debug run is, in a line. */
export function debugLine(run, nameOf = (id) => id) {
  if (!run?.debug) return ''
  if (['done', 'failed', 'stopped'].includes(run.status)) return 'The debug run is over.'
  const stopped = stoppedAt(run)
  if (stopped.length === 1) return `Stopped before ${nameOf(stopped[0].node)}.`
  if (stopped.length > 1) return `Stopped before ${stopped.length} nodes.`
  if ((run.approvals ?? []).some((approval) => approval.status === 'waiting')) return 'Waiting for an approval.'
  return run.debug.stepMode ? 'Going to the next node…' : 'Going to the next breakpoint…'
}
