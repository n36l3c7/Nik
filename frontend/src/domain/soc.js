/*
 * ============================================================================
 * SOC ENGINE — what is left of the client-side detection
 * ============================================================================
 *
 * Since 7.0 the host evidence (event logs, browser, commands, endpoint artifacts) is read by Sigma rules on
 * the server. This engine serves what is still analysed in the browser: the keywords of the Malware tab
 * (strings and indicators of a sample) and the business hours, which mark the events of the other tabs
 * (mail, network, addresses, samples) that fall outside working time.
 *
 * `createSocEngine({ malwareKeywords, businessHours })` compiles the regexes once and analyzes an event:
 * `url`, `title` (opt.), `fileName` (opt.) and a time in `time` (fallback: `visitTime` / `startTime`), in
 * Unix epoch ms. Only an event of `kind: 'malware'` is matched against the keywords.
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
 * Creates the engine from the current settings.
 * The regexes are compiled once; rules with an invalid pattern are silently ignored.
 */
export function createSocEngine({ malwareKeywords = [], businessHours = DEFAULT_BUSINESS_HOURS } = {}) {
  const compiledMalware = malwareKeywords
    .map((rule) => {
      try {
        return { ...rule, regex: new RegExp(rule.pattern, 'i') }
      } catch {
        return null // invalid pattern: rule skipped
      }
    })
    .filter(Boolean)

  /** Keyword rules matching URL + title (+ file name); only malware entries have any. */
  function matchKeywords(entry) {
    if (entry.kind !== 'malware') return []
    const haystack = `${entry.url ?? ''} ${entry.title ?? ''} ${entry.fileName ?? ''}`
    return compiledMalware.filter((rule) => rule.regex.test(haystack))
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

/** An engine that detects nothing, for what only needs the events built (the search palette). */
export const NO_DETECTION_ENGINE = {
  analyze: () => ({ keywordMatches: [], isAnomalousTime: false, severity: null, isFlagged: false }),
  matchKeywords: () => [],
  businessHours: DEFAULT_BUSINESS_HOURS,
}
