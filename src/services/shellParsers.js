/*
 * ============================================================================
 * SHELL HISTORY PARSERS — single entry point for uploaded history files
 * ============================================================================
 *
 * `parseShellHistory(file, shell)` reads the file as text and parses it
 * according to the shell's native format:
 *
 *   - bash:        one command per line; when HISTTIMEFORMAT is set on the
 *                  host, each command is preceded by a `#<epoch>` line
 *   - zsh:         plain lines or EXTENDED_HISTORY `: <epoch>:<dur>;command`
 *                  (multi-line commands continue with a trailing backslash)
 *   - fish:        YAML-like `- cmd: <command>` + `when: <epoch>` pairs
 *   - psreadline:  PowerShell PSReadLine, one command per line; multi-line
 *                  commands continue with a trailing backtick. No timestamps.
 *
 * JSON and CSV exports from forensic tools are accepted regardless of the
 * shell (lenient column mapping, like the browser parsers).
 *
 * Return: { commands: [{ id, command, time, lineNo }], format }
 *   `time` is Unix epoch ms or null when the format has no timestamps.
 */

import Papa from 'papaparse'
import { generateId } from '../utils/id.js'
import { anyToMs } from '../utils/time.js'

/** Epoch seconds (10-11 digits) → Unix ms; anything else → null. */
function epochSecondsToMs(value) {
  const n = Number(value)
  if (!Number.isFinite(n) || n <= 0) return null
  return Math.round(n * 1000)
}

function makeEntry(command, time, lineNo) {
  return { id: generateId(), command, time: time ?? null, lineNo }
}

/* ------------------------------------------------------------------------ */
/* Native text formats                                                       */
/* ------------------------------------------------------------------------ */

/** bash: plain lines, with optional `#<epoch>` timestamp lines interleaved. */
function parseBash(text) {
  const commands = []
  let pendingTime = null
  let lineNo = 0
  for (const rawLine of text.split('\n')) {
    lineNo += 1
    const line = rawLine.replace(/\r$/, '')
    if (!line.trim()) continue
    // HISTTIMEFORMAT marker: "#" + epoch seconds alone on its own line.
    const tsMatch = line.match(/^#(\d{9,11})$/)
    if (tsMatch) {
      pendingTime = epochSecondsToMs(tsMatch[1])
      continue
    }
    commands.push(makeEntry(line, pendingTime, lineNo))
    pendingTime = null
  }
  return commands
}

/** zsh: EXTENDED_HISTORY `: <epoch>:<duration>;command` or plain lines. */
function parseZsh(text) {
  const commands = []
  let lineNo = 0
  let current = null // accumulator for backslash-continued commands
  for (const rawLine of text.split('\n')) {
    lineNo += 1
    const line = rawLine.replace(/\r$/, '')
    if (current) {
      // Continuation of a multi-line command.
      const continued = line.endsWith('\\')
      current.command += '\n' + (continued ? line.slice(0, -1) : line)
      if (!continued) {
        commands.push(current)
        current = null
      }
      continue
    }
    if (!line.trim()) continue
    const extended = line.match(/^:\s*(\d{9,11}):(\d+);([\s\S]*)$/)
    const time = extended ? epochSecondsToMs(extended[1]) : null
    const body = extended ? extended[3] : line
    if (!body.trim() && !extended) continue
    const entry = makeEntry(body.endsWith('\\') ? body.slice(0, -1) : body, time, lineNo)
    if (body.endsWith('\\')) {
      current = entry
    } else {
      commands.push(entry)
    }
  }
  if (current) commands.push(current)
  return commands
}

/** fish: `- cmd: <command>` entries followed by `when: <epoch>`. */
function parseFish(text) {
  const commands = []
  let lineNo = 0
  let current = null
  for (const rawLine of text.split('\n')) {
    lineNo += 1
    const line = rawLine.replace(/\r$/, '')
    const cmdMatch = line.match(/^-\s+cmd:\s?(.*)$/)
    if (cmdMatch) {
      if (current) commands.push(current)
      // fish escapes backslashes and newlines inside the stored command.
      const command = cmdMatch[1].replace(/\\n/g, '\n').replace(/\\\\/g, '\\')
      current = makeEntry(command, null, lineNo)
      continue
    }
    const whenMatch = line.match(/^\s+when:\s?(\d{9,11})/)
    if (whenMatch && current) {
      current.time = epochSecondsToMs(whenMatch[1])
    }
  }
  if (current) commands.push(current)
  return commands
}

/** PSReadLine: plain lines; a trailing backtick continues on the next line. */
function parsePsReadline(text) {
  const commands = []
  let lineNo = 0
  let current = null
  for (const rawLine of text.split('\n')) {
    lineNo += 1
    const line = rawLine.replace(/\r$/, '')
    if (current) {
      const continued = line.endsWith('`')
      current.command += '\n' + (continued ? line.slice(0, -1) : line)
      if (!continued) {
        commands.push(current)
        current = null
      }
      continue
    }
    if (!line.trim()) continue
    const continued = line.endsWith('`')
    const entry = makeEntry(continued ? line.slice(0, -1) : line, null, lineNo)
    if (continued) {
      current = entry
    } else {
      commands.push(entry)
    }
  }
  if (current) commands.push(current)
  return commands
}

const TEXT_PARSERS = {
  bash: parseBash,
  zsh: parseZsh,
  fish: parseFish,
  psreadline: parsePsReadline,
}

/* ------------------------------------------------------------------------ */
/* Lenient JSON / CSV exports (forensic tools)                               */
/* ------------------------------------------------------------------------ */

const COMMAND_ALIASES = ['command', 'cmd', 'commandline', 'command_line', 'line', 'input']
const TIME_ALIASES = ['time', 'timestamp', 'when', 'date', 'datetime', 'executed_at', 'start']

function mapExportRows(rows) {
  const commands = []
  let lineNo = 0
  for (const raw of rows) {
    lineNo += 1
    if (!raw || typeof raw !== 'object') continue
    const normalized = {}
    for (const [key, value] of Object.entries(raw)) {
      normalized[String(key).trim().toLowerCase()] = value
    }
    let command = null
    for (const alias of COMMAND_ALIASES) {
      const value = normalized[alias]
      if (value !== undefined && value !== null && String(value).trim() !== '') {
        command = String(value)
        break
      }
    }
    if (!command) continue
    let time = null
    for (const alias of TIME_ALIASES) {
      const value = normalized[alias]
      if (value !== undefined && value !== null && value !== '') {
        time = anyToMs(value)
        if (time !== null) break
      }
    }
    commands.push(makeEntry(command, time, lineNo))
  }
  return commands
}

function parseJsonExport(text) {
  let parsed
  try {
    parsed = JSON.parse(text)
  } catch {
    return null
  }
  const rows = Array.isArray(parsed)
    ? parsed
    : Array.isArray(parsed?.commands)
      ? parsed.commands
      : Array.isArray(parsed?.history)
        ? parsed.history
        : null
  if (!rows) return null
  return mapExportRows(rows)
}

function parseCsvExport(text) {
  const result = Papa.parse(text.trim(), { header: true, skipEmptyLines: true })
  if (!Array.isArray(result.data) || result.data.length === 0) return null
  const commands = mapExportRows(result.data)
  // Only treat it as a valid CSV export when the command column was found.
  return commands.length > 0 ? commands : null
}

/* ------------------------------------------------------------------------ */
/* Entry point                                                               */
/* ------------------------------------------------------------------------ */

/**
 * Parses an uploaded shell-history file.
 * @param {File} file
 * @param {{ id: string, format: string, label: string }} shell — registry entry
 * @returns {Promise<{ commands: Array, format: 'text'|'json'|'csv' }>}
 */
export async function parseShellHistory(file, shell) {
  const text = await file.text()
  if (!text.trim()) {
    throw new Error('The file is empty.')
  }

  // JSON / CSV exports first (recognizable regardless of the shell format).
  const trimmed = text.trimStart()
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    const commands = parseJsonExport(text)
    if (commands && commands.length > 0) return { commands, format: 'json' }
  }
  if (/\.csv$/i.test(file.name)) {
    const commands = parseCsvExport(text)
    if (commands && commands.length > 0) return { commands, format: 'csv' }
    throw new Error(
      'CSV not recognized: a "command" (or cmd/command_line) column is required.',
    )
  }

  const parser = TEXT_PARSERS[shell.format] ?? parseBash
  const commands = parser(text)
  if (commands.length === 0) {
    throw new Error(
      `No commands found: the file does not look like a ${shell.label} history.`,
    )
  }
  return { commands, format: 'text' }
}
