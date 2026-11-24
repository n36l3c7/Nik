/*
 * The automatic refresh of a screen (the incident list, a dashboard): what it can be set to, how the
 * choice is remembered in this browser, and when the next refresh is due. Pure: lib/useAutoRefresh.js
 * is the hook that runs the timers, components/ui/RefreshControl.jsx what is drawn.
 */

/** What the person can choose; `seconds` 0 is off. */
export const CHOICES = [
  { id: 'off', label: 'Off', seconds: 0 },
  { id: '30s', label: '30 seconds', seconds: 30 },
  { id: '1m', label: '1 minute', seconds: 60 },
  { id: '5m', label: '5 minutes', seconds: 300 },
  { id: '10m', label: '10 minutes', seconds: 600 },
  { id: '30m', label: '30 minutes', seconds: 1800 },
]

/** Off: what the incident list starts with, and what an unknown stored choice means there. */
export const DEFAULT_CHOICE = 'off'
/** On a dashboard: follow the pace the dashboard itself was saved with. */
export const FOLLOW = 'default'

/** A pace in plain words: "Off", "30 seconds", "1 minute", "90 seconds", "2 minutes", "1 hour". */
export function labelOfSeconds(seconds) {
  const known = CHOICES.find((choice) => choice.seconds === seconds)
  if (known) return known.label
  if (!(seconds > 0)) return 'Off'
  const [count, unit] =
    seconds % 3600 === 0
      ? [seconds / 3600, 'hour']
      : seconds % 60 === 0
        ? [seconds / 60, 'minute']
        : [seconds, 'second']
  return `${count} ${unit}${count === 1 ? '' : 's'}`
}

/** What a dashboard's chooser offers: following the dashboard's own pace first, then the explicit ones. */
export function dashboardChoices(defaultSeconds) {
  return [{ id: FOLLOW, label: `Dashboard default (${labelOfSeconds(defaultSeconds)})` }, ...CHOICES]
}

/** The pace in force: the dashboard's own for `default`, else the one chosen (an explicit Off is off). */
export function effectiveSeconds(id, defaultSeconds = 0) {
  if (id === FOLLOW) return defaultSeconds > 0 ? defaultSeconds : 0
  return secondsOf(id)
}

/** The seconds of a choice (0 for off, or for anything unknown). */
export function secondsOf(id) {
  return CHOICES.find((choice) => choice.id === id)?.seconds ?? 0
}

/**
 * The storage key of one account's choice. With a `scope` (a dashboard: `dashboards.<id>`) the choice
 * is that of the account for that screen alone; without, it is the one of the incident list.
 */
export function storageKey(user, scope = null) {
  return scope ? `nik.autoRefresh.${scope}:${user ?? ''}` : `nik.incidents.autoRefresh:${user ?? ''}`
}

const valid = (id, scope) => CHOICES.some((choice) => choice.id === id) || (Boolean(scope) && id === FOLLOW)

/**
 * The choice remembered here: an id of CHOICES (with a scope, also `default`). Nothing kept, an unknown
 * value or a storage that throws gives `default` for a scope (a dashboard) and 'off' for the list.
 */
export function readChoice(storage, user, scope = null) {
  const fallback = scope ? FOLLOW : DEFAULT_CHOICE
  try {
    const kept = storage.getItem(storageKey(user, scope))
    return valid(kept, scope) ? kept : fallback
  } catch {
    return fallback
  }
}

/** Remember the choice (an unknown id is not kept). A storage that refuses leaves it for this visit only. */
export function writeChoice(storage, user, id, scope = null) {
  if (!valid(id, scope)) return
  try {
    storage.setItem(storageKey(user, scope), id)
  } catch {
    // The choice still applies to this visit.
  }
}

/** Milliseconds until the next refresh, `seconds` after the last one ended (`lastAt`, ms); never negative. */
export function dueIn(lastAt, seconds, now) {
  const wait = seconds * 1000
  if (!Number.isFinite(lastAt)) return Math.max(0, wait)
  return Math.max(0, lastAt + wait - now)
}

/**
 * What the timer does now: `{ type: 'wait', ms }` until the next refresh, `{ type: 'refresh' }` at once,
 * `{ type: 'idle' }` when nothing is to be done until something changes (off, a refresh running, paused,
 * the tab hidden). `lastAt` is when the last refresh ended (or when the timer started).
 */
export function nextAction({ seconds, paused = false, hidden = false, refreshing = false, lastAt = null, now }) {
  if (!(seconds > 0) || refreshing || paused || hidden) return { type: 'idle' }
  const ms = dueIn(lastAt, seconds, now)
  return ms > 0 ? { type: 'wait', ms } : { type: 'refresh' }
}

/** A time of day as the control says it: local, with the seconds (14:02:31). */
export function clockTime(ms) {
  return new Date(ms).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  })
}

/** What the control says of the last refresh: when it was, or that it failed (with the last good time, if any). */
export function refreshNote({ lastAt, error }) {
  if (error) return lastAt ? `Could not refresh · ${clockTime(lastAt)}` : 'Could not refresh'
  return lastAt ? `Updated ${clockTime(lastAt)}` : ''
}

/**
 * The refresh signal of the widgets of a screen: a counter the page bumps, which each widget's effect
 * depends on. Pure so it is tested: the next tick, and whether a widget must read again.
 */
export const nextTick = (tick) => (Number.isFinite(tick) ? tick + 1 : 1)
export const shouldReload = (seen, tick) => seen !== tick
