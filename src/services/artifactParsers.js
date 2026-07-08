/*
 * ============================================================================
 * ENDPOINT ARTIFACT PARSER — CSV / JSON exports from DFIR tools
 * ============================================================================
 *
 * `parseArtifactFile(file, category)` reads a CSV or JSON export and maps each
 * row into a record shaped by the category's field aliases (config/artifacts.js).
 * The mapping is deliberately lenient (like the browser/shell parsers): DFIR
 * tools name columns differently, so each field accepts several aliases and the
 * timestamp is recognized from any of the category's `timeAliases`.
 *
 * Return: { records: [{ id, time, fields: {...} }], format: 'csv'|'json' }
 *   `time` is Unix epoch ms or null.
 */

import Papa from 'papaparse'
import { generateId } from '../utils/id.js'
import { anyToMs } from '../utils/time.js'

const asText = (value) => (value === null || value === undefined ? '' : String(value).trim())

function normalizeRow(row) {
  const normalized = {}
  for (const [key, value] of Object.entries(row ?? {})) {
    normalized[String(key).trim().toLowerCase().replace(/[\s_-]+/g, '')] = value
  }
  return normalized
}

/** First non-empty value among the aliases (aliases normalized like headers). */
function pick(normalizedRow, aliases) {
  for (const alias of aliases) {
    const key = alias.toLowerCase().replace(/[\s_-]+/g, '')
    const value = normalizedRow[key]
    if (value !== undefined && value !== null && String(value).trim() !== '') return value
  }
  return null
}

function mapRows(rows, category) {
  const records = []
  for (const raw of rows) {
    if (!raw || typeof raw !== 'object') continue
    const row = normalizeRow(raw)

    const fields = {}
    for (const [fieldKey, aliases] of Object.entries(category.fields)) {
      fields[fieldKey] = asText(pick(row, aliases))
    }

    // A record is meaningful only if its primary field resolved to something.
    if (!fields[category.primaryField]) continue

    const time = anyToMs(pick(row, category.timeAliases))
    records.push({ id: generateId(), time, fields })
  }
  return records
}

function parseJson(text, category) {
  let parsed
  try {
    parsed = JSON.parse(text)
  } catch {
    return null
  }
  const rows = Array.isArray(parsed)
    ? parsed
    : Array.isArray(parsed?.records)
      ? parsed.records
      : Array.isArray(parsed?.rows)
        ? parsed.rows
        : Array.isArray(parsed?.data)
          ? parsed.data
          : null
  if (!rows) return null
  return mapRows(rows, category)
}

function parseCsv(text, category) {
  const result = Papa.parse(text.trim(), { header: true, skipEmptyLines: true })
  if (!Array.isArray(result.data) || result.data.length === 0) return null
  return mapRows(result.data, category)
}

/**
 * @param {File} file
 * @param {object} category — a registry entry from config/artifacts.js
 * @returns {Promise<{ records: Array, format: 'csv'|'json' }>}
 */
export async function parseArtifactFile(file, category) {
  const text = await file.text()
  if (!text.trim()) throw new Error('The file is empty.')

  const trimmed = text.trimStart()
  const looksJson = trimmed.startsWith('{') || trimmed.startsWith('[')

  if (looksJson) {
    const records = parseJson(text, category)
    if (records && records.length > 0) return { records, format: 'json' }
    if (records && records.length === 0) {
      throw new Error(`No "${category.primaryField}" values found in the JSON export.`)
    }
  }

  const records = parseCsv(text, category)
  if (records && records.length > 0) return { records, format: 'csv' }

  throw new Error(
    `Could not map any records: a column for "${category.primaryField}" is required ` +
      '(CSV with a header row, or a JSON array).',
  )
}
