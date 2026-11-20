/*
 * The health page (GET /api/health/details): how its rows are grouped and
 * said, the form of the thresholds, and what an operator copies to point
 * Prometheus at the metrics.
 */

/** The badge of each state of a row. */
export const STATES = {
  fine: { color: 'emerald', text: 'fine' },
  attention: { color: 'amber', text: 'attention' },
  problem: { color: 'red', text: 'problem' },
  unknown: { color: 'slate', text: 'not known' },
}

export const stateBadge = (state) => STATES[state] ?? STATES.unknown

const ORDER = { problem: 0, attention: 1, unknown: 2, fine: 3 }

/** The rows by group, the groups in the order the server gives them. */
export function groupRows(rows = []) {
  const groups = []
  for (const row of rows) {
    let group = groups.find((candidate) => candidate.name === row.group)
    if (!group) {
      group = { name: row.group, rows: [], worst: 'fine' }
      groups.push(group)
    }
    group.rows.push(row)
    if ((ORDER[row.state] ?? 3) < ORDER[group.worst] && row.state !== 'unknown') group.worst = row.state
  }
  return groups
}

/** The rows that are not fine, the worst first: what the top of the page lists. */
export const needingAttention = (rows = []) =>
  rows
    .filter((row) => row.state === 'problem' || row.state === 'attention')
    .sort((a, b) => ORDER[a.state] - ORDER[b.state])

/** One sentence for the whole page. */
export function summary(counts = {}) {
  const problems = counts.problem ?? 0
  const attention = counts.attention ?? 0
  const unknown = counts.unknown ?? 0
  const said = []
  if (problems) said.push(`${problems} ${problems === 1 ? 'problem' : 'problems'}`)
  if (attention) said.push(`${attention} ${attention === 1 ? 'thing needs' : 'things need'} attention`)
  const head = said.length ? `${said.join(', ')}.` : 'Everything that could be measured is fine.'
  return unknown ? `${head} ${unknown} could not be measured.` : head
}

/** The thresholds as the form holds them: name → what is typed. */
export const thresholdsForm = (thresholds = []) =>
  Object.fromEntries(thresholds.map((entry) => [entry.name, String(entry.value)]))

/** Why the form cannot be saved, or null. */
export function thresholdsProblem(form, thresholds = []) {
  for (const entry of thresholds) {
    const typed = String(form[entry.name] ?? '').trim()
    const value = /^\d+$/.test(typed) ? Number(typed) : NaN
    if (!(value >= entry.min && value <= entry.max)) {
      return `${entry.label}: a whole number from ${entry.min} to ${entry.max}.`
    }
  }
  return null
}

/** What is sent to PUT /health/thresholds: the thresholds that changed. */
export function thresholdsBody(form, thresholds = []) {
  const body = {}
  for (const entry of thresholds) {
    const value = Number(String(form[entry.name] ?? '').trim())
    if (value !== entry.value) body[entry.name] = value
  }
  return body
}

/**
 * The scrape job an operator adds to prometheus.yml. `origin` is the address the browser
 * uses for Nik (https://nik.example:8443); the token goes into a file beside the configuration.
 */
export function scrapeConfig(origin) {
  let host = 'nik.example:8443'
  let scheme = 'https'
  try {
    const url = new URL(origin)
    host = url.host
    scheme = url.protocol.replace(':', '')
  } catch {
    // An address that cannot be read: the example stands.
  }
  return [
    'scrape_configs:',
    '  - job_name: nik',
    `    scheme: ${scheme}`,
    '    metrics_path: /api/metrics',
    '    authorization:',
    '      type: Bearer',
    '      credentials_file: /etc/prometheus/nik-metrics-token',
    '    tls_config:',
    '      ca_file: /etc/prometheus/nik-ca.crt  # the certificate of Nik, or of its authority',
    '    static_configs:',
    `      - targets: ["${host}"]`,
  ].join('\n')
}
