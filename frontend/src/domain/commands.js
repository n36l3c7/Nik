/*
 * What the Command History page (components/tabs/commands) works out from the files of the server.
 */

/**
 * The files of a command history, by shell: `{ [shell]: { sources, count, partial } }`. `partial` is a file read
 * in part that nobody looked at (the yellow dot of the selector); the count is what was kept.
 */
export function groupByShell(sources = []) {
  const groups = {}
  for (const source of sources) {
    const group = (groups[source.source] ??= { sources: [], count: 0, partial: false })
    group.sources.push(source)
    group.count += Number.isFinite(source.kept) ? source.kept : 0
    if (source.state === 'done' && source.read === 'partial' && !source.seen) group.partial = true
  }
  return groups
}

/** The distinct non-empty values of a field of the files (`username`, `host`), sorted. */
export function distinctOf(sources = [], field) {
  return [...new Set(sources.map((source) => source[field]).filter(Boolean))].sort((a, b) => a.localeCompare(b))
}

/**
 * The order the commands of a shell open in: the newest first when any file has times, else by time too in
 * its ascending form, which lists the commands without a time file by file, each in its own order.
 */
export function defaultOrderFor(sources = []) {
  return sources.length > 0 && sources.every((source) => source.firstTs == null && source.lastTs == null)
    ? 'time'
    : '-time'
}

/** The number shown in "#": the line of the command in its file (the worker's), else its place (`seq` counts from 0). */
export function lineOf(row) {
  const line = row?.data?.line
  if (Number.isFinite(line)) return line
  return Number.isFinite(row?.seq) ? row.seq + 1 : null
}

/** The sentence under "With timestamp" when the shell keeps none. */
export function noTimeText(shellLabel, withTime, total) {
  return total > 0 && withTime === 0
    ? `${shellLabel} history keeps none: listed file by file, in file order`
    : undefined
}
