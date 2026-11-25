/*
 * The time zones the business hours can be told in: IANA names, as the browser lists them. UTC comes
 * first (some browsers leave it out of the list) and is the default when the server has none.
 */

export const DEFAULT_TIME_ZONE = 'UTC'

/** The IANA names the browser knows, UTC first, each once. `supported` is for tests. */
export function timeZones(supported) {
  let names = supported
  if (!names) {
    try {
      names = Intl.supportedValuesOf('timeZone')
    } catch {
      names = []
    }
  }
  return [DEFAULT_TIME_ZONE, ...new Set(names.filter((name) => name !== DEFAULT_TIME_ZONE))]
}

/** The zone a settings document names, or UTC when it names none or the key is absent. */
export const zoneOf = (businessHours) =>
  typeof businessHours?.tz === 'string' && businessHours.tz.trim() ? businessHours.tz.trim() : DEFAULT_TIME_ZONE

/** The name as written, when the list has it (case aside), else ''. */
export function matchZone(text, zones) {
  const wanted = String(text ?? '')
    .trim()
    .toLowerCase()
  return zones.find((name) => name.toLowerCase() === wanted) ?? ''
}
