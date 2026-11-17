/*
 * SLA timers (GET /api/incidents/<id>/timers, the `sla` of an incident type)
 * as the screens read them: how long a time is in words, what a timer says,
 * and the rules of a type as the form of Settings edits them.
 */

export const SEVERITIES = ['low', 'medium', 'high', 'critical']

/** A length of time in words: "45 s", "12 min", "1 h 20 min", "2 d 3 h". */
export function span(seconds) {
  const total = Math.max(0, Math.round(Number(seconds) || 0))
  if (total < 60) return `${total} s`
  const minutes = Math.round(total / 60)
  if (minutes < 60) return `${minutes} min`
  if (minutes < 48 * 60) {
    const hours = Math.floor(minutes / 60)
    return minutes % 60 ? `${hours} h ${minutes % 60} min` : `${hours} h`
  }
  const days = Math.floor(minutes / 1440)
  const hours = Math.round((minutes % 1440) / 60)
  return hours ? `${days} d ${hours} h` : `${days} d`
}

/**
 * What a timer says, as the server shows it: `{ text, tone }` with `tone`
 * 'ok' | 'late' | 'muted'.
 */
export function timerLine(timer) {
  const counted = span(timer?.elapsedS)
  const late = Boolean(timer?.breached)
  const over = timer?.dueS ? span(timer.elapsedS - timer.dueS) : ''
  switch (timer?.state) {
    case 'running':
      if (!timer.dueS) return { text: `running · ${counted}`, tone: 'ok' }
      return late
        ? { text: `${over} over · of ${span(timer.dueS)}`, tone: 'late' }
        : { text: `${span(timer.remainingS)} left · of ${span(timer.dueS)}`, tone: 'ok' }
    case 'paused':
      return { text: `paused at ${counted}`, tone: late ? 'late' : 'muted' }
    case 'stopped':
      return late
        ? { text: `took ${counted} · ${over} over`, tone: 'late' }
        : { text: `took ${counted}`, tone: 'muted' }
    default:
      return { text: 'not started', tone: 'muted' }
  }
}

/** A timer as the registry stores it (no clock to read it against), in a few words. */
export function storedTimer(value) {
  if (!value || typeof value !== 'object') return ''
  const state = value.state ?? 'idle'
  const late = value.breached_at ? ' · past its time' : ''
  if (state === 'running') return `running${late}`
  return `${state} at ${span(value.accumulated_s)}${late}`
}

/** The timers that still run: what makes a screen read them again. */
export const anyRunning = (timers) => (timers ?? []).some((timer) => timer.state === 'running')

/* ------------------------------------------------------- the SLA of a type */

/**
 * The SLA of a type as rows of a form, one per timer field there is:
 * `{ field, label, on, minutes, bySeverity: { low, … }, businessHours }`,
 * numbers as the texts an input holds.
 */
export function slaRows(type, fields) {
  const rules = Object.fromEntries((type?.sla ?? []).map((rule) => [rule.field, rule]))
  return (fields ?? [])
    .filter((field) => field.type === 'timer' && field.appliesTo === 'incident')
    .map((field) => {
      const rule = rules[field.name]
      return {
        field: field.name,
        label: field.label || field.name,
        on: Boolean(rule),
        minutes: rule ? String(rule.minutes) : '',
        bySeverity: Object.fromEntries(SEVERITIES.map((name) => [name, String(rule?.bySeverity?.[name] ?? '')])),
        businessHours: Boolean(rule?.businessHours),
      }
    })
}

const whole = (text) => (/^\d+$/.test(String(text).trim()) ? Number(text) : null)

/** Why the rows cannot be saved (a sentence), or null. */
export function slaProblem(rows) {
  for (const row of rows ?? []) {
    if (!row.on) continue
    const minutes = whole(row.minutes)
    if (!minutes) return `${row.label}: say how many minutes are allowed`
    for (const name of SEVERITIES) {
      const typed = String(row.bySeverity?.[name] ?? '').trim()
      if (typed && !whole(typed)) return `${row.label}: the time for ${name} is a number of minutes`
    }
  }
  return null
}

/** What PUT /api/incident-types/<id> takes as `sla`, from the rows. */
export function slaOf(rows) {
  return (rows ?? [])
    .filter((row) => row.on)
    .map((row) => ({
      field: row.field,
      minutes: whole(row.minutes),
      bySeverity: Object.fromEntries(
        SEVERITIES.filter((name) => whole(row.bySeverity?.[name])).map((name) => [name, whole(row.bySeverity[name])]),
      ),
      businessHours: row.businessHours,
    }))
}

/** The hours business time is counted in, in words. */
export function hoursText(hours) {
  if (!hours) return ''
  const pad = (hour) => `${String(hour).padStart(2, '0')}:00`
  return `${pad(hours.startHour)}–${pad(hours.endHour)} UTC${hours.flagWeekends ? ', Monday to Friday' : ', every day'}`
}

/* ----------------------------------------------------------- notifications */

/** What a notification is about, as a word for its badge. */
export function notificationKind(kind) {
  switch (kind) {
    case 'task':
      return 'task'
    case 'task.reminder':
      return 'reminder'
    case 'task.overdue':
      return 'overdue'
    case 'approval':
      return 'approval'
    case 'mention':
      return 'mention'
    case 'sla.breached':
      return 'SLA'
    default:
      return 'notice'
  }
}

/** Only a path inside Nik is followed from a notification. */
export const safeLink = (link) => (/^\/[A-Za-z0-9]/.test(String(link ?? '')) ? String(link) : null)
