/*
 * The library of nodes (GET /api/automation/catalog) as the canvas uses it:
 * its groups, the node an entry becomes when it is dropped, what a node is
 * called, and the values the expressions of a node can pick.
 */
import { CONTEXT_FIELDS, INCIDENT_FIELDS as REGISTRY_FIELDS } from '../context.js'
import { IN_LOOP, newId, nodeOf, readable, triggerOf } from './graph.js'

/** The trigger is not in the library (a playbook has exactly one), so it is described here. */
export const TRIGGER_ENTRY = {
  id: 'flow.trigger',
  kind: 'trigger',
  group: 'Flow',
  name: 'Trigger',
  description: 'What starts the playbook: an event, a schedule, a request from outside, or a person.',
  arguments: [],
  outputs: [],
}

const INCIDENT_FIELDS = [
  ['id', 'text', 'Its id'],
  ['url', 'text', 'Its address in Nik'],
  ['name', 'text', 'Its name'],
  ['ticket', 'text', 'The ticket id'],
  ['status', 'text', 'open, in_progress or closed'],
  ['severity', 'text', 'low, medium, high or critical'],
  ['assignee', 'text', 'Who has it'],
  ['host', 'text', 'The host'],
  ['username', 'text', 'The user'],
  ['os', 'text', 'The operating system'],
  ['created', 'text', 'When it was created'],
  ['modified', 'text', 'When it last changed'],
].map(([name, type, description]) => ({ name: `incident.${name}`, type, description }))

const fieldsOf = (prefix, rows) =>
  rows.map(([name, type, description]) => ({ name: `${prefix}.${name}`, type, description }))

const MAIL_FIELDS = fieldsOf('mail', [
  ['sha256', 'text', 'The SHA-256 of the message'],
  ['subject', 'text', 'Its subject'],
  ['sender', 'text', "The sender's address"],
  ['sender_domain', 'text', "The domain of the sender's address"],
  ['sender_sha256', 'text', "The SHA-256 of the sender's address: names the sender without giving the address"],
  ['verdict', 'text', 'phishing, suspicious or clean'],
  ['score', 'number', 'Its score, 0 to 100'],
  ['urls', 'list', 'The addresses its links lead to'],
  ['attachments', 'list', 'Its attachments: each with name, sha256 and size'],
  ['artifact_id', 'text', 'Its id as an artifact'],
  ['url', 'text', 'Its address in Nik'],
])

const FILE_FIELDS = fieldsOf('file', [
  ['sha256', 'text', 'The SHA-256 of the file'],
  ['name', 'text', 'Its name'],
  ['size', 'number', 'Its size in bytes'],
  ['type', 'text', 'What kind of file it is'],
  ['verdict', 'text', 'high, medium or empty'],
  ['yara', 'list', 'The names of the YARA rules that matched'],
  ['artifact_id', 'text', 'Its id as an artifact'],
  ['url', 'text', 'Its address in Nik'],
])

const SCAN_FIELDS = fieldsOf('scan', [
  ['id', 'text', 'The id of the scan'],
  ['url', 'text', 'The address that was scanned'],
  ['final_url', 'text', 'Where it led'],
  ['host', 'text', 'The host of the address'],
  ['verdict', 'text', 'phishing, suspicious or clean'],
  ['score', 'number', 'Its score, 0 to 100'],
  ['artifact_id', 'text', 'Its id as an artifact'],
  ['page', 'text', 'Its address in Nik'],
])

const IOC_FIELDS = fieldsOf('ioc', [
  ['kind', 'text', 'ip, domain, url, email, md5, sha1 or sha256'],
  ['value', 'text', 'The indicator'],
  ['verdict', 'text', 'malicious, suspicious, harmless, unknown or empty'],
  ['score', 'number', 'The reputation score'],
  ['tlp', 'text', 'Its TLP, when it has one'],
  ['tags', 'list', 'Its tags'],
  ['lists', 'list', 'The names of its lists'],
  ['incidents', 'number', 'In how many incidents it was seen'],
  ['private', 'bool', 'It is a private address or an internal name'],
  ['allowlisted', 'bool', 'It is in the allowlist'],
])

const INCIDENT_OPTIONAL = [...INCIDENT_FIELDS.map((field) => ({ ...field, optional: true }))]

/** The events a trigger can wait for: what each is called, what it is about, a filter to start from. */
export const EVENTS = {
  'incident.created': { label: 'An incident is created', about: 'incident', sample: ['incident.severity', 'high'] },
  'incident.updated': { label: 'An incident changes', about: 'incident', sample: ['incident.status', 'closed'] },
  'mail.analysed': { label: 'An e-mail is analysed', about: 'mail', sample: ['mail.verdict', 'phishing'] },
  'file.analysed': { label: 'A file is analysed', about: 'file', sample: ['file.verdict', 'high'] },
  'url.analysed': { label: 'An address is scanned', about: 'url', sample: ['scan.verdict', 'phishing'] },
  'ioc.verdict_changed': {
    label: "An indicator's verdict changes",
    about: 'indicator',
    sample: ['ioc.new', 'malicious'],
  },
  'ioc.watch_hit': {
    label: 'An incident holds a watched indicator',
    about: 'incident',
    sample: ['list.name', 'My watched list'],
  },
  'storage.low': { label: 'The disk is nearly full', about: '', sample: ['disk.free_percent', 5] },
  'sla.breached': {
    label: 'A timer of an incident passes its time',
    about: 'incident',
    sample: ['timer.field', 'time_to_contain'],
  },
  'artifact.expiring': {
    label: 'An artifact with a date is a week from being deleted',
    about: '',
    sample: ['artifact.kind', 'mailbox'],
  },
  'artifact.expired': {
    label: 'An artifact was deleted because its date came',
    about: '',
    sample: ['artifact.kind', 'mailbox'],
  },
}

/** An event as the inspector lists it: "An e-mail is analysed · mail.analysed". */
export const eventLabel = (event) => (EVENTS[event] ? `${EVENTS[event].label} · ${event}` : event)

/** A first filter for an event, for the analyst to change. */
export function sampleFilter(event) {
  const [field, value] = EVENTS[event]?.sample ?? ['incident.severity', 'high']
  return { all: [{ left: `{{ trigger.${field} }}`, op: typeof value === 'number' ? 'lt' : 'eq', right: value }] }
}

/** What a trigger's event is about: incident, mail, file, url, indicator, or nothing. */
export const runsOn = (config = {}) => EVENTS[config.event]?.about ?? ''

const NAMES = {
  incident: 'an incident',
  mail: 'an e-mail',
  file: 'a file',
  url: 'a scanned address',
  indicator: 'an indicator',
}
/** "an e-mail", for what a playbook runs on. */
export const objectName = (about) => NAMES[about] ?? 'nothing'

function eventFields(event) {
  switch (event) {
    case 'incident.created':
      return INCIDENT_FIELDS
    case 'incident.updated':
      return [...INCIDENT_FIELDS, { name: 'changed', type: 'list', description: 'The fields that changed' }]
    case 'mail.analysed':
      return [
        ...MAIL_FIELDS,
        { name: 'from_mailbox', type: 'text', description: 'The id of the mailbox it was imported from, or empty' },
        ...INCIDENT_OPTIONAL,
      ]
    case 'file.analysed':
      return [...FILE_FIELDS, ...INCIDENT_OPTIONAL]
    case 'url.analysed':
      return SCAN_FIELDS
    case 'ioc.verdict_changed':
      return [
        ...IOC_FIELDS,
        { name: 'ioc.old', type: 'text', description: 'The verdict before (empty when it had none)' },
        { name: 'ioc.new', type: 'text', description: 'The verdict now' },
        { name: 'ioc.sources', type: 'list', description: 'The sources that answered' },
      ]
    case 'ioc.watch_hit':
      return [
        ...IOC_FIELDS,
        { name: 'list.id', type: 'text', description: 'The id of the watched list' },
        { name: 'list.name', type: 'text', description: 'Its name' },
        { name: 'hits', type: 'list', description: 'Every hit: each with type, value, list and incident' },
        ...INCIDENT_FIELDS,
      ]
    case 'sla.breached':
      return [
        ...fieldsOf('timer', [
          ['field', 'text', 'The timer: time_to_assign, time_to_contain, time_to_close…'],
          ['label', 'text', 'Its name'],
          ['due_minutes', 'number', 'The time it was allowed'],
          ['elapsed_minutes', 'number', 'What it had counted'],
        ]),
        ...INCIDENT_FIELDS,
      ]
    case 'artifact.expiring':
    case 'artifact.expired':
      return fieldsOf('artifact', [
        ['id', 'text', 'Its id in Nik'],
        ['kind', 'text', 'file, mail, pcap, url or mailbox'],
        ['name', 'text', 'Its name'],
        ['ref', 'text', 'Its SHA-256, or the id of a capture or a scan'],
        ['size', 'number', 'Its size in bytes'],
        ['expires_at', 'text', 'The day it is deleted on'],
        ['days_left', 'number', 'The days left (0 once it was deleted)'],
        ['url', 'text', 'Its page in Nik'],
      ])
    case 'storage.low':
      return fieldsOf('disk', [
        ['total', 'number', 'The size of the disk in bytes'],
        ['used', 'number', 'Bytes in use'],
        ['free', 'number', 'Bytes free'],
        ['free_percent', 'number', 'How much is free, in percent'],
      ])
    default:
      return []
  }
}

/** What `{{ trigger.… }}` holds, by what starts the playbook. */
export function triggerFields(config = {}) {
  const fields = []
  if (config.event) fields.push(...eventFields(config.event))
  if (config.manual) {
    fields.push({ name: 'actor', type: 'text', description: 'Who started the run' })
    if (!config.event) fields.push(...INCIDENT_OPTIONAL)
  }
  if (config.webhook) {
    fields.push({ name: 'body', type: 'any', description: 'What was sent: an object when it is JSON, text otherwise' })
    fields.push({ name: 'headers', type: 'object', description: 'Content type, user agent and the X- headers' })
    fields.push({ name: 'query', type: 'object', description: 'What follows the ? in the address' })
  }
  if (config.cron) {
    fields.push({ name: 'at', type: 'text', description: 'When the schedule fired' })
    fields.push({ name: 'cron', type: 'text', description: 'The schedule' })
  }
  return fields
}

const RUN_FIELDS = [
  { name: 'id', type: 'text', description: 'The id of this run' },
  { name: 'url', type: 'text', description: 'Its address in Nik' },
  { name: 'playbook', type: 'text', description: "The playbook's name" },
  { name: 'started_at', type: 'text', description: 'When it started' },
  { name: 'dry_run', type: 'bool', description: 'Whether it is a dry run' },
]

const list = (value) => (Array.isArray(value) ? value : [])

/** The library in groups: Flow, Nik, the connectors as the server lists them, then HTTP, E-mail and Scripts. */
const GROUP_RANK = { Flow: 0, Nik: 1, HTTP: 3, 'E-mail': 4, Scripts: 5 }
export function groupsOf(entries, query = '') {
  const words = String(query).toLowerCase().split(/\s+/).filter(Boolean)
  const groups = new Map()
  for (const entry of list(entries)) {
    // Kept for the playbooks that have it (the e-mail node of 4.x): not offered for new nodes.
    if (entry.retired) continue
    const haystack = `${entry.name} ${entry.group} ${entry.description ?? ''} ${entry.id}`.toLowerCase()
    if (!words.every((word) => haystack.includes(word))) continue
    if (!groups.has(entry.group)) groups.set(entry.group, [])
    groups.get(entry.group).push(entry)
  }
  const rank = (name) => GROUP_RANK[name] ?? 2
  return [...groups].map(([name, found]) => ({ name, entries: found })).sort((a, b) => rank(a.name) - rank(b.name))
}

/** The library entry a node was made from; null when it is gone (an action or a script removed). */
export function entryOf(node, entries) {
  if (!node) return null
  if (node.kind === 'trigger') return TRIGGER_ENTRY
  const all = list(entries)
  if (node.kind === 'action')
    return all.find((entry) => entry.kind === 'action' && entry.id === node.config?.action) ?? null
  if (node.kind === 'script') {
    const found = all.find((entry) => entry.kind === 'script' && entry.script === node.config?.script)
    // The node stays on the version it was saved with; the entry is the current one.
    return found ?? null
  }
  return all.find((entry) => entry.kind === node.kind && entry.group === 'Flow') ?? null
}

const defaults = (declared) =>
  Object.fromEntries(
    list(declared)
      .filter((argument) => argument.default !== undefined && argument.default !== null)
      .map((argument) => [argument.name, argument.default]),
  )

/** Who a task or a question is for, in words. */
export function forWhom(assignee, nobody) {
  if (assignee?.user) return assignee.user
  if (assignee?.role) return `the role ${assignee.role}`
  return assignee?.owner ? 'the owner' : nobody
}

/** The settings a node starts with. */
export function startingConfig(entry) {
  switch (entry.kind) {
    case 'trigger':
      return { manual: true }
    case 'condition':
      return { all: [{ left: '', op: 'eq', right: '' }] }
    case 'for_each':
      return { items: '', max: 500 }
    case 'wait':
      return { seconds: 300 }
    case 'approval':
      return { question: '' }
    case 'task':
      return { title: '', assignee: { owner: true } }
    case 'ask':
      return { question: '', choices: ['Yes', 'No'] }
    case 'action':
      return { action: entry.id, args: defaults(entry.arguments) }
    case 'script':
      return { script: entry.script, script_version: entry.version, args: defaults(entry.arguments) }
    case 'playbook':
      return { playbook: '', args: {}, wait: true }
    case 'end':
      return { status: 'done', message: '' }
    default:
      return {}
  }
}

/** The node an entry of the library becomes on the canvas. */
export function nodeFrom(entry, graph, position) {
  return {
    id: newId(graph, entry.kind === 'action' ? entry.id.split('.').at(-1) : entry.name),
    kind: entry.kind,
    name: entry.kind === 'playbook' ? 'Run another playbook' : entry.name,
    position: { x: Math.round(position.x), y: Math.round(position.y) },
    config: startingConfig(entry),
  }
}

/** A free place for a node added without a drop: under the lowest node, or under `after`. */
export function freePosition(graph, after = null) {
  const anchor = after ? nodeOf(graph, after) : null
  const nodes = list(graph?.nodes)
  if (anchor) {
    let spot = { x: anchor.position.x, y: anchor.position.y + 110 }
    while (nodes.some((node) => Math.abs(node.position.x - spot.x) < 150 && Math.abs(node.position.y - spot.y) < 60)) {
      spot = { x: spot.x + 220, y: spot.y }
    }
    return spot
  }
  if (nodes.length === 0) return { x: 40, y: 40 }
  const lowest = nodes.reduce((found, node) => (node.position.y > found.position.y ? node : found))
  return { x: lowest.position.x, y: lowest.position.y + 110 }
}

/** The small line over a node's name: "Action · Nik", "Script · GroupByField". */
export function headingOf(node, entry) {
  switch (node.kind) {
    case 'action':
      return `Action · ${entry?.group ?? 'missing'}`
    case 'script':
      return `Script · ${node.config?.script ?? ''}`
    case 'for_each':
      return 'For each'
    case 'playbook':
      return 'Playbook'
    default:
      return node.kind.charAt(0).toUpperCase() + node.kind.slice(1)
  }
}

const duration = (seconds) => {
  if (!Number.isFinite(seconds)) return ''
  if (seconds % 86400 === 0) return `${seconds / 86400} d`
  if (seconds % 3600 === 0) return `${seconds / 3600} h`
  return `${Math.round(seconds / 60)} min`
}

/** What a node says about itself under its name, from its settings. */
export function summaryOf(node, entry) {
  const config = node.config ?? {}
  switch (node.kind) {
    case 'trigger': {
      const ways = []
      if (config.event) ways.push(config.event)
      if (config.cron) ways.push(`schedule ${config.cron}`)
      if (config.webhook) ways.push('webhook')
      if (config.manual) ways.push('by hand')
      return ways.join(' · ') || 'not set yet'
    }
    case 'condition': {
      const key = config.any ? 'any' : 'all'
      const count = list(config[key]).length
      return count === 1 ? '1 comparison' : `${key} of ${count} comparisons`
    }
    case 'for_each':
      return config.items ? `each of ${config.items}` : 'no list yet'
    case 'wait':
      return config.until
        ? `until a condition · ${duration(config.timeout ?? 86400)} at most`
        : duration(config.seconds)
    case 'approval':
      return `${config.question || 'no question yet'} · ${config.wait_seconds ? `waits ${duration(config.wait_seconds)}` : 'waits without limit'}`
    case 'task':
      return `${config.title || 'nothing to do yet'} · for ${forWhom(config.assignee, 'the owner')}`
    case 'ask':
      return `${config.question || 'no question yet'} · to ${forWhom(config.assignee, 'anyone')}`
    case 'action': {
      if (!entry) return 'this action does not exist any more'
      // Named as its action: what it is given says more than the name twice.
      const given = Object.entries(config.args ?? {}).find(([, value]) => value !== '' && value !== null)
      if (node.name && node.name !== entry.name) return entry.name
      return given
        ? `${given[0]}: ${typeof given[1] === 'string' ? given[1] : JSON.stringify(given[1])}`
        : entry.description || entry.name
    }
    case 'script':
      return entry ? `version ${config.script_version}` : 'this script does not exist any more'
    case 'playbook':
      return config.playbook || 'no playbook yet'
    case 'end':
      return config.status === 'failed'
        ? `failed${config.message ? `: ${config.message}` : ''}`
        : config.message || 'done'
    default:
      return ''
  }
}

/** True when the node asks a person before it runs (its own setting, else what it does and the playbook's default). */
export function asksApproval(node, entry, approvalDefault = true) {
  if (node.kind !== 'action') return false
  const asked = node.config?.approval?.ask
  if (typeof asked === 'boolean') return asked
  return Boolean(entry?.changesOutside) && approvalDefault
}

const SUB_DEPTH = 3
const SUB_MAX = 60

const typeOf = (value) =>
  Array.isArray(value)
    ? 'list'
    : value === null || value === undefined
      ? 'any'
      : typeof value === 'object'
        ? 'object'
        : typeof value === 'boolean'
          ? 'bool'
          : typeof value === 'number'
            ? 'number'
            : 'text'

/**
 * What is inside a value, as paths under `name`: the keys of an object, and
 * for a list the keys of its first item (`name[0].key`). Three levels deep at
 * most: enough to reach what a block gives without listing a whole document.
 */
export function subFields(name, value, depth = SUB_DEPTH) {
  if (depth <= 0 || value === null || typeof value !== 'object') return []
  if (Array.isArray(value)) {
    if (value.length === 0) return []
    const first = `${name}[0]`
    const inside = subFields(first, value[0], depth - 1)
    // A list of plain values: its first one is worth a path of its own.
    return typeof value[0] === 'object' && value[0] !== null
      ? inside
      : [{ name: first, type: typeOf(value[0]), description: `The first of ${name}` }]
  }
  const found = []
  for (const key of Object.keys(value).slice(0, 20)) {
    // A key that is not a plain name is read with brackets; such keys are rare and left out.
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue
    const path = `${name}.${key}`
    found.push({ name: path, type: typeOf(value[key]), description: `Inside ${name}` })
    found.push(...subFields(path, value[key], depth - 1))
  }
  return found
}

/**
 * The outputs of a block, each followed by what is inside it when the block
 * says what an answer looks like (`sample`, from the connector's file).
 */
export function withSubFields(outputs, sample) {
  if (!sample || typeof sample !== 'object' || Array.isArray(sample)) return outputs
  const out = []
  for (const output of outputs) {
    out.push(output)
    if (output.name in sample) out.push(...subFields(output.name, sample[output.name]))
    if (out.length >= SUB_MAX) break
  }
  return out.slice(0, SUB_MAX)
}

/**
 * The values the expressions of a node can pick, as a tree:
 * `[{ name, label, fields: [{ path, type, description }] }]`. `path` is what
 * goes between the braces.
 */
export function valueTree(graph, id, entries) {
  const { nodes, loop, poll } = readable(graph, id)
  const trigger = triggerOf(graph)
  const roots = []
  const push = (name, label, fields) =>
    roots.push({
      name,
      label,
      fields: fields.map((field) => ({ ...field, path: field.name ? `${name}.${field.name}` : name })),
    })
  if (trigger) push('trigger', 'What started the run', triggerFields(trigger.config))
  for (const other of nodes) {
    const node = nodeOf(graph, other)
    if (!node || node.kind === 'trigger' || node.kind === 'end') continue
    const entry = entryOf(node, entries)
    const outputs = withSubFields(list(entry?.outputs), entry?.sample)
    push(
      node.id,
      node.name || node.id,
      outputs.length ? outputs : [{ name: '', type: 'any', description: 'What the node gave' }],
    )
  }
  if (loop) {
    push('item', 'The item of this turn', [{ name: '', type: 'any', description: `One of the items of "${loop}"` }])
    push('index', 'Its position', [{ name: '', type: 'number', description: 'Counted from 0' }])
  }
  if (poll)
    push('poll', 'The last answer', [{ name: '', type: 'any', description: 'What the action asked again gave' }])
  const inputs = list(graph?.inputs).filter((input) => input?.name)
  if (inputs.length) {
    push(
      'inputs',
      'Inputs of the playbook',
      inputs.map((input) => ({ name: input.name, type: input.type ?? 'text', description: input.description ?? '' })),
    )
  }
  push('run', 'This run', RUN_FIELDS)
  // The incident the run works on, as it is when the step runs, and what is known of it.
  push('incident', 'The incident, now', REGISTRY_FIELDS)
  push('context', 'The context of the incident', CONTEXT_FIELDS)
  return roots
}

export { IN_LOOP }
