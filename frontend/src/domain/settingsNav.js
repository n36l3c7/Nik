/*
 * The Settings page: its groups, its sections and their addresses.
 *
 * Every section has an address of its own, /settings/<group>/<section>, so a
 * link opens it, the browser's Back leaves it and a reload stays on it. A
 * section names the permission it needs (the server enforces the same split);
 * `permission: null` is for every signed-in account.
 *
 * Later releases add sections and groups here (automation, incidents,
 * integrations, lists): a group that has no section the account can open is
 * simply not shown.
 */

export const SETTINGS_ROOT = '/settings'

/**
 * `id` is what the code names a section by (and what older links used);
 * `slug` is its part of the address. `keywords` are what the search box
 * matches besides the label.
 */
export const SETTINGS_GROUPS = [
  {
    id: 'analysis',
    label: 'Analysis',
    sections: [
      {
        id: 'detection',
        slug: 'detection-rules',
        label: 'Detection rules',
        permission: 'read',
        keywords: 'keywords suspicious patterns categories severity',
      },
      {
        id: 'hours',
        slug: 'business-hours',
        label: 'Business hours',
        permission: 'read',
        keywords: 'working time off-hours weekend timezone',
      },
      {
        id: 'mail',
        slug: 'mail-analysis',
        label: 'Mail analysis',
        permission: 'admin',
        keywords: 'e-mail organisation domains trusted authentication servers spf dkim',
      },
      {
        id: 'report',
        slug: 'report-header',
        label: 'Report header',
        permission: 'admin',
        keywords: 'branding logo organisation pdf tlp',
      },
    ],
  },
  {
    id: 'indicators',
    label: 'Indicators',
    sections: [
      {
        id: 'allowlist',
        slug: 'allowlist',
        label: 'IOC allowlist',
        permission: 'read',
        keywords: 'indicators known good internal addresses networks domains',
      },
      {
        id: 'intel',
        slug: 'threat-intelligence',
        label: 'Threat intelligence',
        permission: 'admin',
        keywords: 'sources connectors instances api keys virustotal reputation lookups retention automatic enrichment',
      },
    ],
  },
  {
    id: 'rules',
    label: 'Rule sets',
    sections: [
      { id: 'yara', slug: 'yara', label: 'YARA rules', permission: 'rules.manage', keywords: 'malware signatures' },
      {
        id: 'capa',
        slug: 'capa',
        label: 'capa rules',
        permission: 'rules.manage',
        keywords: 'capabilities malware behaviour',
      },
      {
        id: 'flirt',
        slug: 'flirt',
        label: 'FLIRT signatures',
        permission: 'rules.manage',
        keywords: 'library functions disassembly sig pat',
      },
      {
        id: 'scriptSignatures',
        slug: 'script-signatures',
        label: 'Script signatures',
        permission: 'rules.manage',
        keywords: 'javascript url analysis scripts regex pattern keylogger grabber obfuscation',
      },
    ],
  },
  {
    id: 'incidents',
    label: 'Incidents',
    sections: [
      {
        id: 'incidentTypes',
        slug: 'types',
        label: 'Types',
        permission: 'incidents.configure',
        keywords: 'incident type fields layout sections page close reasons phishing malware builder',
      },
      {
        id: 'fields',
        slug: 'all-fields',
        label: 'All fields',
        permission: 'incidents.configure',
        keywords: 'registry custom field name label choice table rename delete',
      },
      {
        id: 'sla',
        slug: 'sla',
        label: 'SLA',
        permission: 'incidents.configure',
        keywords: 'timer time to assign contain close minutes severity business hours breach deadline',
      },
      {
        id: 'preprocess',
        slug: 'pre-processing',
        label: 'Pre-processing rules',
        permission: 'incidents.configure',
        keywords: 'fetch alerts drop duplicate link existing dedup noise script before incident',
      },
    ],
  },
  {
    id: 'lists',
    label: 'Lists',
    sections: [
      {
        id: 'lists',
        slug: 'all',
        label: 'Lists',
        permission: 'lists.manage',
        keywords: 'allowlist domains keywords business hours hosts values import export csv json watch vip',
      },
    ],
  },
  {
    id: 'automation',
    label: 'Automation',
    sections: [
      {
        id: 'contentPacks',
        slug: 'content-packs',
        label: 'Content packs',
        permission: 'content.manage',
        keywords:
          'nikpack import export share bundle install uninstall update catalogue marketplace vendor product playbooks connectors types dashboards file',
      },
      {
        id: 'connectors',
        slug: 'connectors',
        label: 'Connectors',
        permission: 'connectors.manage',
        // Fetching, the classifier and the mappers are set in the instance (6.4): their words lead here.
        keywords:
          'integrations yaml file commands products servicenow jira upload samples instances connections credentials address token test systems ' +
          'fetch status alerts incoming polling interval how often first fetch look-back lookback reset last run failing paused items incomplete ' +
          'classifiers classify type mappers mapping fields vendor outgoing sample expression mirror queue',
      },
      {
        id: 'credentials',
        slug: 'credentials',
        label: 'Credentials',
        permission: 'connectors.manage',
        keywords:
          // Not "password": that word finds My account, where a person changes their own.
          'secrets stored api key token user name username pair vault shared reuse instances connectors variable reinstall',
      },
      {
        id: 'automationNetwork',
        slug: 'network-and-data',
        label: 'Network and data',
        permission: 'admin',
        keywords: 'playbooks hosts egress allowed smtp e-mail server what leaves',
      },
      {
        id: 'automationSwitch',
        slug: 'stop-all',
        label: 'Stop all',
        permission: 'admin',
        keywords: 'playbooks switch kill pause worker running',
      },
    ],
  },
  {
    id: 'access',
    label: 'Access',
    sections: [
      { id: 'account', slug: 'my-account', label: 'My account', permission: null, keywords: 'password roles me' },
      {
        id: 'accounts',
        slug: 'accounts',
        label: 'Accounts and roles',
        permission: 'admin',
        keywords: 'users people permissions disable admin analyst viewer',
      },
      {
        id: 'apikeys',
        slug: 'api-keys',
        label: 'API keys',
        permission: 'admin',
        keywords: 'tokens integrations scripts rest',
      },
    ],
  },
  {
    id: 'system',
    label: 'System',
    sections: [
      {
        id: 'storage',
        slug: 'storage',
        label: 'Storage',
        permission: 'admin',
        keywords: 'disk space free largest files mailboxes captures',
      },
      {
        id: 'workers',
        slug: 'workers',
        label: 'Workers',
        permission: 'admin',
        keywords: 'health status down answering analyzer capa browser sandbox pcap document containers notifications',
      },
      {
        id: 'backup',
        slug: 'backup',
        label: 'Backup',
        permission: 'admin',
        keywords: 'export restore full platform schedule retention passphrase snapshot upgrade verify sftp copy',
      },
      {
        id: 'audit',
        slug: 'audit-log',
        label: 'Audit log',
        permission: 'audit.read',
        keywords: 'history who did what',
      },
    ],
  },
]

const SECTIONS = SETTINGS_GROUPS.flatMap((group) => group.sections.map((section) => ({ ...section, group: group.id })))
const BY_ID = new Map(SECTIONS.map((section) => [section.id, section]))

/** The section with this id, or null. */
export const settingsSection = (id) => BY_ID.get(id) ?? null

/** The address of a section (by id); of the page itself when the id is unknown. */
export function settingsPath(id) {
  const section = BY_ID.get(id)
  return section ? `${SETTINGS_ROOT}/${section.group}/${section.slug}` : SETTINGS_ROOT
}

export const isSettingsPath = (pathname) => /^\/settings(\/|$)/.test(String(pathname ?? ''))

const MOVED_TO_CONNECTORS = new Set(['connections', 'fetch-status', 'classifiers-and-mappers'])

/** The parts of the form of an instance, in the order of its tabs. */
export const INSTANCE_TABS = ['connection', 'keys', 'fetch', 'classifier', 'mappers']

/** The address that opens an instance on Connectors, on one part of its form. */
export function instancePath(instanceId, tab = '') {
  const base = `${settingsPath('connectors')}/${encodeURIComponent(instanceId)}`
  return INSTANCE_TABS.includes(tab) && tab !== 'connection' ? `${base}/${tab}` : base
}

/**
 * The instance an address of Connectors names, and the part of its form:
 * `{ instanceId, tab }`, or null when it names none (the page alone, or another section).
 */
export function instanceFromPath(pathname) {
  const path = String(pathname ?? '').split('?')[0]
  if (settingsFromPath(path)?.id !== 'connectors') return null
  const [, , , slug, instanceId, tab] = path.replace(/\/+$/, '').split('/')
  if (slug !== 'connectors' || !instanceId) return null
  let id = instanceId
  try {
    id = decodeURIComponent(instanceId)
  } catch {
    // A stray % in the address: taken as it is written.
  }
  return { instanceId: id, tab: INSTANCE_TABS.includes(tab) ? tab : 'connection' }
}

/** The address of Credentials with one credential pointed at (by its name). */
export const credentialPath = (name) => `${settingsPath('credentials')}/${encodeURIComponent(name)}`

/** The credential an address of Credentials points at (its name), or '' when it names none. */
export function credentialFromPath(pathname) {
  const path = String(pathname ?? '').split('?')[0]
  if (settingsFromPath(path)?.id !== 'credentials') return ''
  const [, , , slug, name] = path.replace(/\/+$/, '').split('/')
  if (slug !== 'credentials' || !name) return ''
  try {
    return decodeURIComponent(name)
  } catch {
    return name
  }
}

/**
 * What a path asks for: null when it is not the Settings page; otherwise
 * `{ id }` with the section's id, or `{ id: null }` for /settings alone or an
 * address that names no section (the page then opens its first one).
 */
export function settingsFromPath(pathname) {
  const path = String(pathname ?? '')
  if (!isSettingsPath(path)) return null
  const [, , group, slug] = path.replace(/\/+$/, '').split('/')
  const section = SECTIONS.find((candidate) => candidate.group === group && candidate.slug === slug)
  if (section) return { id: section.id }
  // An address of 4.x: the connections are the instances of the connectors now. And the pages that
  // 6.4 moved into the instance: fetching, the classifier and the mappers are set there.
  if (group === 'automation' && MOVED_TO_CONNECTORS.has(slug)) return { id: 'connectors' }
  // /settings/<group>: its first section. An id of an older link (/settings/audit) is understood too.
  const first = SECTIONS.find((candidate) => candidate.group === group)
  return { id: first?.id ?? (BY_ID.has(group) ? group : null) }
}

/** The groups and sections an account can open, given its `can(permission)`. */
export function visibleSettings(can) {
  return SETTINGS_GROUPS.map((group) => ({
    ...group,
    sections: group.sections.filter((section) => !section.permission || can(section.permission)),
  })).filter((group) => group.sections.length > 0)
}

/** The section to show: the one asked for when the account can open it, its first one otherwise. */
export function resolveSection(groups, id) {
  const all = groups.flatMap((group) => group.sections)
  return all.find((section) => section.id === id) ?? all[0] ?? null
}

/** The groups narrowed to the sections whose label, group or keywords hold every word typed. */
export function filterSettings(groups, query) {
  const words = String(query ?? '')
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
  if (words.length === 0) return groups
  return groups
    .map((group) => ({
      ...group,
      sections: group.sections.filter((section) => {
        const text = `${section.label} ${group.label} ${section.keywords ?? ''}`.toLowerCase()
        return words.every((word) => text.includes(word))
      }),
    }))
    .filter((group) => group.sections.length > 0)
}
