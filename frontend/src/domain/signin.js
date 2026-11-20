/*
 * Signing in: what the screens of the second factor, of the sessions and of
 * the sign-in policy decide, without the screens.
 *
 * The server holds the rules (backend/app/signin.py, core/signin_policy.py).
 * What is here is the page's side: which requests are the person's and which
 * are its own, when to warn that a session is about to end, how a browser and
 * a wait are named, what a typed code or network is.
 */

// ---------------------------------------------------------------------------
// The person, or the page?
// ---------------------------------------------------------------------------
// A request sent this long after the person last did something (a key, a click, the wheel) is theirs.
// Later ones are the page's own (a list that refreshes, a count that is asked again): they are sent
// with `X-Nik-Background`, and the server does not count them as the session being used.
export const ACTIVE_MS = 10_000

/** Whether a request sent now is the page's own, given when the person last did something. */
export function isBackground(lastInteraction, now) {
  return now - lastInteraction > ACTIVE_MS
}

/**
 * How often the server is told that the person is there while they work without any request being
 * sent (typing a long note): a quarter of the idle time, between ten seconds and a minute.
 */
export function keepAliveMs(idleSeconds) {
  if (!idleSeconds) return 60_000
  return Math.max(10_000, Math.min(60_000, (idleSeconds * 1000) / 4))
}

/** Whether the person doing something now is worth telling the server, given the last request of theirs. */
export function needsKeepAlive(lastForeground, now, everyMs) {
  return now - lastForeground >= everyMs
}

// ---------------------------------------------------------------------------
// When a session ends
// ---------------------------------------------------------------------------
// The page asks the server how long is left when its own count says the warning is this near.
const CHECK_AHEAD_MS = 45_000
// A session is warned about this long before its lifetime is over (nothing extends that).
const LIFETIME_WARN_MS = 60_000

/**
 * What the page keeps of `{ idleSeconds, idleLeft, lifetimeLeft, warnSeconds }` (GET /api/auth/session),
 * as moments of its own clock. `confirmed`: these are the server's numbers, not the page's guess.
 */
export function sessionClock(state, now) {
  if (!state) return null
  return {
    idleMs: (state.idleSeconds || 0) * 1000,
    warnMs: (state.warnSeconds || 0) * 1000,
    idleEndsAt: state.idleLeft === null || state.idleLeft === undefined ? null : now + state.idleLeft * 1000,
    lifetimeEndsAt: now + (state.lifetimeLeft || 0) * 1000,
    confirmed: true,
  }
}

/** The clock after a request of the person: the server counts the idle time again from now (a guess until asked). */
export function clockAfterUse(clock, now) {
  if (!clock || !clock.idleMs) return clock
  return { ...clock, idleEndsAt: now + clock.idleMs, confirmed: false }
}

/**
 * Where a session stands: `fine`; `check` (near enough the end that the server is asked); `warn`
 * (the person is told, `left` seconds before the end); `over`. `reason` says which limit: `idle`
 * (staying signed in is offered) or `lifetime` (it is not).
 */
export function sessionPhase(clock, now) {
  if (!clock) return { phase: 'fine', reason: null, left: null }
  const idleLeft = clock.idleEndsAt === null ? Infinity : clock.idleEndsAt - now
  const lifeLeft = clock.lifetimeEndsAt - now
  const reason = lifeLeft <= idleLeft ? 'lifetime' : 'idle'
  const leftMs = Math.min(idleLeft, lifeLeft)
  const warnMs = reason === 'idle' ? clock.warnMs : LIFETIME_WARN_MS
  const left = Math.max(0, Math.ceil(leftMs / 1000))
  if (leftMs <= 0) return { phase: 'over', reason, left: 0 }
  if (leftMs <= warnMs) return { phase: clock.confirmed ? 'warn' : 'check', reason, left }
  if (leftMs <= warnMs + CHECK_AHEAD_MS) return { phase: 'check', reason, left }
  return { phase: 'fine', reason, left }
}

/** Seconds as a countdown: "0:42", "12:05". */
export function countdown(seconds) {
  const whole = Math.max(0, Math.round(seconds))
  return `${Math.floor(whole / 60)}:${String(whole % 60).padStart(2, '0')}`
}

/** A number of minutes in words: "30 minutes", "1 hour", "8 hours", "1 hour 30 minutes", "never" for 0. */
export function minutesWords(minutes) {
  if (!minutes) return 'never'
  const hours = Math.floor(minutes / 60)
  const rest = minutes % 60
  const parts = []
  if (hours) parts.push(`${hours} hour${hours === 1 ? '' : 's'}`)
  if (rest) parts.push(`${rest} minute${rest === 1 ? '' : 's'}`)
  return parts.join(' ')
}

// ---------------------------------------------------------------------------
// Codes
// ---------------------------------------------------------------------------
export const CODE_LENGTH = 6

/** What was typed or pasted in the code field: its digits, six at most ("123 456" is 123456). */
export function cleanCode(typed) {
  return String(typed ?? '')
    .replace(/\D/g, '')
    .slice(0, CODE_LENGTH)
}

export const isCode = (code) => new RegExp(`^\\d{${CODE_LENGTH}}$`).test(code)

/** A secret in groups of four, as people read it out to type it in an app. */
export function groupedSecret(secret) {
  return (
    String(secret ?? '')
      .match(/.{1,4}/g)
      ?.join(' ') ?? ''
  )
}

/** The file of recovery codes a person downloads. */
export function recoveryCodesFile(codes, username, when = new Date()) {
  return [
    `Nik recovery codes for ${username}`,
    `Made on ${when.toISOString().slice(0, 10)}`,
    '',
    'Each code signs you in once, in place of the code of your authenticator app.',
    'Keep them where your password is not. Making new codes ends these.',
    '',
    ...codes,
    '',
  ].join('\n')
}

/** What is said of the recovery codes that are left after one was used. */
export function recoveryCodesLeftText(left) {
  if (left === 0) {
    return 'That was your last recovery code. Make new ones now, in Settings → My account: without them, a lost device locks you out.'
  }
  if (left === 1) return 'That recovery code is spent. You have 1 left: make new ones in Settings → My account.'
  return `That recovery code is spent. You have ${left} left.`
}

// ---------------------------------------------------------------------------
// Accounts and sessions
// ---------------------------------------------------------------------------
/** The second factor of an account, for the list: `on`, `missing` (its roles ask for one) or `off`. */
export function factorState(user) {
  if (user?.secondFactor) return 'on'
  return user?.secondFactorRequired ? 'missing' : 'off'
}

export const FACTOR_LABELS = { on: 'Second factor', missing: 'Second factor required', off: 'No second factor' }

/** Whether the account can do nothing before it has set a second factor up. */
export const mustEnrol = (user) => factorState(user) === 'missing'

const BROWSERS = [
  [/\bEdg(?:e|A|iOS)?\/(\d+)/, 'Edge'],
  [/\bOPR\/(\d+)/, 'Opera'],
  [/\bVivaldi\/(\d+)/, 'Vivaldi'],
  [/\bFirefox\/(\d+)/, 'Firefox'],
  [/\bFxiOS\/(\d+)/, 'Firefox'],
  [/\bCriOS\/(\d+)/, 'Chrome'],
  [/\bHeadlessChrome\/(\d+)/, 'Chrome'],
  [/\bChrom(?:e|ium)\/(\d+)/, 'Chrome'],
  [/\bVersion\/(\d+)[.\d]* (?:Mobile\/\S+ )?Safari\//, 'Safari'],
]
const SYSTEMS = [
  [/iPhone|iPad|iPod/, 'iOS'],
  [/Android/, 'Android'],
  [/Windows NT/, 'Windows'],
  [/Mac OS X|Macintosh/, 'macOS'],
  [/CrOS/, 'ChromeOS'],
  [/Linux|X11/, 'Linux'],
]
const TOOLS = [
  [/^curl\//, 'curl'],
  [/python-requests|python-httpx|^Python/i, 'a Python script'],
  [/^Go-http-client/, 'a Go program'],
  [/PowerShell/i, 'PowerShell'],
  [/^Wget\//, 'wget'],
]

/** A browser as a person would name it: "Firefox 140 on Linux". "An unknown browser" when nothing is recognised. */
export function browserName(userAgent) {
  const agent = String(userAgent ?? '')
  if (!agent.trim()) return 'An unknown browser'
  for (const [pattern, name] of TOOLS) if (pattern.test(agent)) return name
  const system = SYSTEMS.find(([pattern]) => pattern.test(agent))?.[1]
  for (const [pattern, name] of BROWSERS) {
    const found = agent.match(pattern)
    if (found) return `${name} ${found[1]}${system ? ` on ${system}` : ''}`
  }
  return system ? `A browser on ${system}` : 'An unknown browser'
}

// ---------------------------------------------------------------------------
// The policy form
// ---------------------------------------------------------------------------
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/

function isIpv6(text) {
  if (!/^[0-9a-f:.]+$/i.test(text) || !text.includes(':')) return false
  const halves = text.split('::')
  if (halves.length > 2) return false
  const groups = halves.flatMap((half) => (half ? half.split(':') : []))
  // An IPv4 address may close an IPv6 one; it stands for two groups.
  const last = groups[groups.length - 1] ?? ''
  const tail = last.includes('.') ? (IPV4.test(last) ? 2 : NaN) : 0
  const plain = tail ? groups.slice(0, -1) : groups
  if (Number.isNaN(tail) || plain.some((group) => !/^[0-9a-f]{1,4}$/i.test(group))) return false
  const count = plain.length + tail
  return halves.length === 2 ? count < 8 : count === 8
}

/** Whether a line is an address or a network the server will take: 10.1.0.0/16, 2001:db8::/32, 192.0.2.7. */
export function isNetwork(line) {
  const [address, prefix, ...more] = String(line ?? '')
    .trim()
    .split('/')
  if (more.length || !address) return false
  const v4 = IPV4.test(address)
  if (!v4 && !isIpv6(address)) return false
  if (prefix === undefined) return true
  return /^\d{1,3}$/.test(prefix) && Number(prefix) <= (v4 ? 32 : 128)
}

/** The networks typed in the box, one per line or separated by commas: `{ networks, wrong }`. */
export function parseNetworks(text) {
  const entries = String(text ?? '')
    .split(/[\n,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean)
  const networks = [...new Set(entries)]
  return { networks, wrong: networks.filter((entry) => !isNetwork(entry)) }
}

export const NUMBER_FIELDS = [
  'idleMinutes',
  'idleMinutesAdmin',
  'lifetimeHours',
  'attemptsBeforeWait',
  'firstWaitSeconds',
  'maxWaitMinutes',
  'notifyAfter',
]

/** The form of the policy screen from the policy the server gave. */
export function policyForm(policy) {
  const form = {
    requiredRoles: [...(policy?.requiredRoles ?? [])],
    adminNetworks: (policy?.adminNetworks ?? []).join('\n'),
  }
  for (const name of NUMBER_FIELDS) form[name] = String(policy?.[name] ?? '')
  return form
}

/**
 * What the form would send, and what is wrong with it: `{ body, problems }`, `problems` by field name.
 * `body` holds only what differs from `policy`.
 */
export function policyChanges(form, policy, limits = {}) {
  const body = {}
  const problems = {}
  for (const name of NUMBER_FIELDS) {
    const text = String(form[name] ?? '').trim()
    const value = Number(text)
    const { min = 0, max = Infinity } = limits[name] ?? {}
    if (!/^\d+$/.test(text) || value < min || value > max) {
      problems[name] = `A whole number from ${min} to ${max}`
      continue
    }
    if (value !== policy[name]) body[name] = value
  }
  if (!problems.firstWaitSeconds && !problems.maxWaitMinutes) {
    if (Number(form.firstWaitSeconds) > Number(form.maxWaitMinutes) * 60) {
      problems.firstWaitSeconds = 'The first wait cannot be longer than the longest one'
    }
  }
  const roles = [...form.requiredRoles].sort()
  if (roles.join() !== [...(policy.requiredRoles ?? [])].sort().join()) body.requiredRoles = form.requiredRoles
  const { networks, wrong } = parseNetworks(form.adminNetworks)
  if (wrong.length) {
    problems.adminNetworks = `Not a network: ${wrong.slice(0, 3).join(', ')}. Write 10.1.0.0/16, 2001:db8::/32 or a single address`
  } else if (!sameNetworks(networks, policy.adminNetworks ?? [])) {
    body.adminNetworks = networks
  }
  return { body, problems }
}

// The server writes a single address as /32 or /128: typed without it, it is the same network.
const bare = (network) => (network.includes(':') ? network.replace(/\/128$/, '') : network.replace(/\/32$/, ''))
const sameNetworks = (typed, stored) => {
  const a = typed.map((entry) => bare(entry.toLowerCase())).sort()
  const b = stored.map((entry) => bare(entry.toLowerCase())).sort()
  return a.join('\n') === b.join('\n')
}

/** The accounts a list of required roles would send to set a second factor up: those with one of the roles and none. */
export function accountsToEnrol(users, requiredRoles) {
  const required = new Set(requiredRoles)
  return (users ?? []).filter(
    (user) => !user.disabled && !user.secondFactor && (user.roles ?? []).some((role) => required.has(role)),
  )
}
