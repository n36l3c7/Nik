/*
 * ============================================================================
 * COMMAND EVENT MODEL — Command History tab
 * ============================================================================
 *
 * Shell-history entries are normalized into the same event shape used by the
 * browser sections (`eventType`, `time`, `soc`), so flags, the Summary
 * timeline and the SOC engine work identically for commands.
 */

/**
 * Enriches raw command entries with `eventType`, `kind` and `soc`.
 * The command line is passed to the engine as `title`, which is part of the
 * keyword haystack (url + title + fileName).
 * @returns Array sorted by time desc (entries without a time sink last).
 */
export function buildCommandEvents({ commands = [], engine }) {
  const events = commands.map((entry) => {
    const event = {
      ...entry,
      kind: 'command',
      eventType: 'command',
      time: Number.isFinite(entry.time) ? entry.time : null,
      title: entry.command,
    }
    event.soc = engine.analyze({ kind: 'command', title: entry.command, time: event.time })
    return event
  })
  return events.sort((a, b) => (b.time ?? -Infinity) - (a.time ?? -Infinity))
}

// Leading tokens that wrap the real executable and should be skipped when
// ranking binaries (plus VAR=value environment assignments).
const WRAPPER_TOKENS = new Set(['sudo', 'time', 'nohup', 'env', 'doas', 'nice', 'xargs'])

/**
 * First "real" executable of a command line: skips sudo/env wrappers and
 * VAR=value assignments, strips the directory part of the path.
 */
export function extractBinary(command) {
  const tokens = String(command ?? '')
    .trim()
    .split(/\s+/)
  for (const token of tokens) {
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token)) continue // env assignment
    const bare = token.replace(/^["']|["']$/g, '')
    const base = bare.split(/[\\/]/).pop()?.toLowerCase() ?? ''
    if (!base) continue
    if (WRAPPER_TOKENS.has(base)) continue
    return base
  }
  return null
}

/** Top N executables by frequency: [{ binary, count }] sorted descending. */
export function topBinaries(commands = [], limit = 5) {
  const counts = new Map()
  for (const entry of commands) {
    const binary = extractBinary(entry.command)
    if (!binary) continue
    counts.set(binary, (counts.get(binary) ?? 0) + 1)
  }
  return [...counts.entries()]
    .map(([binary, count]) => ({ binary, count }))
    .sort((a, b) => b.count - a.count || a.binary.localeCompare(b.binary))
    .slice(0, limit)
}
