/*
 * ============================================================================
 * SOC DETECTION ENGINE
 * ============================================================================
 *
 * The rules (keywords + business hours) are no longer static: they come from
 * the platform Settings (SettingsContext). An "engine" is created with
 * `createSocEngine({ keywords, businessHours })` which compiles the regexes
 * once and analyzes any event (history visit or download).
 *
 * An analyzable event has: `url`, `title` (opt.), `fileName` (opt., for
 * downloads) and a time in `time` (fallback: `visitTime` / `startTime`), in
 * Unix epoch ms.
 *
 * To add a NEW type of detection (beyond keywords) extend `analyze()` below
 * and show the new field in the UI. See README.md.
 */

import { DEFAULT_BUSINESS_HOURS } from '../config/detectionRules.js'

/** Extracts the time (Unix ms) from an event, whatever field is used. */
function timeOf(entry) {
  return entry.time ?? entry.visitTime ?? entry.startTime ?? null
}

/**
 * True if the timestamp falls OUTSIDE the configured business hours.
 * Outside hours = hour < startHour or hour >= endHour; additionally, if
 * `flagWeekends` is enabled, the whole weekend is considered outside hours.
 */
export function isOutsideBusinessHours(ms, businessHours = DEFAULT_BUSINESS_HOURS) {
  if (!Number.isFinite(ms)) return false
  const date = new Date(ms)
  const { startHour, endHour, flagWeekends } = businessHours
  if (flagWeekends) {
    const day = date.getDay() // 0 = Sunday, 6 = Saturday
    if (day === 0 || day === 6) return true
  }
  const hour = date.getHours()
  return hour < startHour || hour >= endHour
}

/**
 * Creates a detection engine from the current settings.
 * The regexes are compiled once; rules with an invalid pattern are silently
 * ignored (the Settings UI validates the input).
 */
export function createSocEngine({ keywords = [], businessHours = DEFAULT_BUSINESS_HOURS } = {}) {
  const compiled = keywords
    .map((rule) => {
      try {
        return { ...rule, regex: new RegExp(rule.pattern, 'i') }
      } catch {
        return null // invalid pattern: rule skipped
      }
    })
    .filter(Boolean)

  /** Keyword rules matching URL + title (+ file name for downloads). */
  function matchKeywords(entry) {
    const haystack = `${entry.url ?? ''} ${entry.title ?? ''} ${entry.fileName ?? ''}`
    return compiled.filter((rule) => rule.regex.test(haystack))
  }

  /**
   * Full analysis of an event. Returns:
   * { keywordMatches, isAnomalousTime, severity: 'high'|'medium'|null, isFlagged }
   */
  function analyze(entry) {
    const keywordMatches = matchKeywords(entry)
    const isAnomalousTime = isOutsideBusinessHours(timeOf(entry), businessHours)

    let severity = null
    if (keywordMatches.some((rule) => rule.severity === 'high')) severity = 'high'
    else if (keywordMatches.length > 0 || isAnomalousTime) severity = 'medium'

    return { keywordMatches, isAnomalousTime, severity, isFlagged: severity !== null }
  }

  return { analyze, matchKeywords, businessHours }
}

/**
 * Aggregate statistics for the stat cards. Receives already-enriched events:
 * [{ ...entry, soc }]. Counts flagged, time anomalies and high severity.
 */
export function computeSocStats(enrichedEntries) {
  let flagged = 0
  let anomalousTime = 0
  let high = 0
  for (const entry of enrichedEntries) {
    if (entry.soc.isFlagged) flagged += 1
    if (entry.soc.isAnomalousTime) anomalousTime += 1
    if (entry.soc.severity === 'high') high += 1
  }
  return { flagged, anomalousTime, high, total: enrichedEntries.length }
}
