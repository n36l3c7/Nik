import { CirclePlay, HardDrive, KeyRound, Usb } from 'lucide-react'
import {
  EXEC_WIN_BAM,
  PERS_WIN_RUN,
  PERS_WIN_TASKS,
  PERS_WIN_SERVICES,
  PERS_WIN_STARTUP,
  PERS_WIN_WMI,
  PERS_LINUX_SYSTEMD,
  USB_WIN_USBSTOR,
  USB_LINUX_JOURNAL,
} from './collectionScripts.js'

/*
 * ============================================================================
 * ENDPOINT ARTIFACT REGISTRY — the only file to edit to add a category/source
 * ============================================================================
 *
 * The "Endpoint Artifacts" tab shows a sub-tab per category. Each category is a
 * flaggable table fed by one or more SOURCES; the table shows the union of
 * every source's records, tagged by which source produced them.
 *
 * A source is imported in one of two ways (never a third-party tool):
 *   - mode 'file'   → upload the EXISTING raw file from the host; a dedicated
 *                     in-browser parser (config: `parser`) turns it into
 *                     records. Used when the data already lives in a plain
 *                     text/XML/log/SQLite file.
 *   - mode 'script' → run the shown native script (OS built-ins only) which
 *                     writes a CSV; import that CSV. Used for live system state
 *                     (registry, service manager, kernel journal) that is not a
 *                     simple file to copy.
 *
 * Artifacts that can only be recovered with third-party DFIR tools (Prefetch,
 * Amcache, ShimCache, UserAssist, LNK, JumpLists, ShellBags, RecentDocs) are
 * intentionally NOT included — there is no fully-custom way to collect them.
 *
 * Category shape:
 *   id / label / icon / accent
 *   primaryField   record field used as the row title and flag label
 *   columns        [{ key, label, mono?, grow?, align? }] shown in the table
 *   fields         { fieldKey: [aliases] } — lenient mapping for CSV/JSON import
 *   timeAliases    aliases for the record timestamp (CSV/JSON import)
 *   detectFields   record fields concatenated into the SOC keyword haystack
 *   sources        { windows|macos|linux: [source] } driven by the host OS
 *
 * Source shape (per OS):
 *   key            unique within the category (data slot + de-dup)
 *   name           label shown in the collection list
 *   path           where the data lives (file path or registry location)
 *   mode           'file' | 'script'
 *   parser         (file) one of 'xbel'|'configlines'|'plist'|'setupapi'|'knowledgec'
 *   accept         (file) input accept filter
 *   recordKind     (configlines) the `kind` stamped on each parsed line
 *   recordName     (configlines) the `name` stamped on each parsed line
 *   script         (script) { lang, code } shown with copy/download
 *   tool           short label describing the method
 */

/* ---- Program execution -------------------------------------------------- */
const EXECUTION = {
  id: 'execution',
  label: 'Program Execution',
  icon: CirclePlay,
  accent: 'text-emerald-500',
  primaryField: 'name',
  columns: [
    { key: 'name', label: 'Executable', mono: true, grow: true },
    { key: 'path', label: 'Path', mono: true, grow: true },
    { key: 'runCount', label: 'Runs', align: 'right' },
    { key: 'source', label: 'Artifact' },
  ],
  fields: {
    name: ['name', 'program', 'executable', 'application', 'filename', 'process', 'value'],
    path: ['path', 'fullpath', 'full_path', 'file_path', 'image', 'devicepath', 'programpath'],
    runCount: ['runcount', 'run_count', 'count', 'executioncount', 'timesexecuted'],
    source: ['source', 'artifact', 'sourcetype', 'type', 'hive'],
  },
  timeAliases: [
    'lastrun', 'last_run', 'lastexecuted', 'last_executed', 'runtime', 'executiontime',
    'timestamp', 'time', 'lastmodified', 'date', 'lastruntime',
  ],
  detectFields: ['name', 'path'],
  sources: {
    windows: [
      { key: 'bam', name: 'BAM/DAM last execution', path: 'SYSTEM hive → …\\Services\\bam\\State\\UserSettings', mode: 'script', script: EXEC_WIN_BAM, tool: 'native PowerShell' },
    ],
    macos: [
      { key: 'knowledgec', name: 'KnowledgeC app usage', path: '~/Library/Application Support/Knowledge/knowledgeC.db', mode: 'file', parser: 'knowledgec', accept: '.db,.sqlite', tool: 'SQLite (parsed in-browser)' },
    ],
    linux: [],
  },
}

/* ---- Persistence -------------------------------------------------------- */
const PERSISTENCE = {
  id: 'persistence',
  label: 'Persistence',
  icon: KeyRound,
  accent: 'text-amber-500',
  primaryField: 'name',
  columns: [
    { key: 'name', label: 'Name', grow: true },
    { key: 'kind', label: 'Type' },
    { key: 'command', label: 'Command / Target', mono: true, grow: true },
    { key: 'location', label: 'Location', mono: true },
  ],
  fields: {
    name: ['name', 'entry', 'task', 'service', 'key', 'label', 'value'],
    kind: ['kind', 'type', 'mechanism', 'category'],
    command: ['command', 'commandline', 'command_line', 'target', 'path', 'action', 'exec', 'data'],
    location: ['location', 'source', 'hive', 'file', 'registrykey', 'key_path'],
  },
  timeAliases: ['created', 'modified', 'lastmodified', 'timestamp', 'time', 'date', 'lastwrite'],
  detectFields: ['name', 'command', 'location'],
  sources: {
    windows: [
      { key: 'runkeys', name: 'Run / RunOnce keys', path: 'NTUSER.dat & SOFTWARE → …\\CurrentVersion\\Run', mode: 'script', script: PERS_WIN_RUN, tool: 'native PowerShell' },
      { key: 'tasks', name: 'Scheduled Tasks', path: 'C:\\Windows\\System32\\Tasks\\', mode: 'script', script: PERS_WIN_TASKS, tool: 'native PowerShell' },
      { key: 'services', name: 'Services', path: 'SYSTEM hive → …\\Services', mode: 'script', script: PERS_WIN_SERVICES, tool: 'native PowerShell' },
      { key: 'startup', name: 'Startup folder', path: '%APPDATA%\\…\\Start Menu\\Programs\\Startup', mode: 'script', script: PERS_WIN_STARTUP, tool: 'native PowerShell' },
      { key: 'wmi', name: 'WMI subscriptions', path: 'root\\Subscription', mode: 'script', script: PERS_WIN_WMI, tool: 'native PowerShell' },
    ],
    linux: [
      { key: 'cron', name: 'cron', path: '/etc/crontab, /etc/cron.d/*, /var/spool/cron/*', mode: 'file', parser: 'configlines', accept: '', recordKind: 'cron', recordName: 'cron entry', tool: 'upload the cron file' },
      { key: 'sshkeys', name: 'SSH authorized_keys', path: '~/.ssh/authorized_keys', mode: 'file', parser: 'configlines', accept: '', recordKind: 'authorized_keys', recordName: 'authorized_key', tool: 'upload the file' },
      { key: 'rc', name: 'shell rc / profile', path: '~/.bashrc, ~/.profile, /etc/rc.local', mode: 'file', parser: 'configlines', accept: '', recordKind: 'shell rc', recordName: 'rc line', tool: 'upload the file' },
      { key: 'systemd', name: 'enabled systemd units', path: '/etc/systemd/system/, ~/.config/systemd/user/', mode: 'script', script: PERS_LINUX_SYSTEMD, tool: 'native systemctl' },
    ],
    macos: [
      { key: 'launch', name: 'LaunchAgent / LaunchDaemon', path: '~/Library/LaunchAgents/*.plist, /Library/Launch*', mode: 'file', parser: 'plist', accept: '.plist,.xml', tool: 'upload the .plist (XML)' },
      { key: 'cron', name: 'cron', path: '/usr/lib/cron/tabs/*', mode: 'file', parser: 'configlines', accept: '', recordKind: 'cron', recordName: 'cron entry', tool: 'upload the cron file' },
    ],
  },
}

/* ---- File & folder access ---------------------------------------------- */
const FILE_ACCESS = {
  id: 'fileaccess',
  label: 'File & Folder Access',
  icon: HardDrive,
  accent: 'text-sky-500',
  primaryField: 'name',
  columns: [
    { key: 'name', label: 'Item', grow: true },
    { key: 'target', label: 'Target path', mono: true, grow: true },
    { key: 'kind', label: 'Evidence' },
  ],
  fields: {
    name: ['name', 'item', 'file', 'filename', 'document', 'label', 'value'],
    target: ['target', 'targetpath', 'target_path', 'path', 'localpath', 'href'],
    kind: ['kind', 'type', 'artifact', 'source'],
  },
  timeAliases: ['accessed', 'lastaccessed', 'modified', 'visited', 'timestamp', 'time', 'date'],
  detectFields: ['name', 'target'],
  // Windows/macOS file-access forensics (LNK, JumpLists, ShellBags, sfl) can
  // only be parsed with third-party tools, so no custom source is offered.
  sources: {
    windows: [],
    macos: [],
    linux: [
      { key: 'recent', name: 'GTK recently-used', path: '~/.local/share/recently-used.xbel', mode: 'file', parser: 'xbel', accept: '.xbel,.xml', tool: 'upload the file (XML)' },
    ],
  },
}

/* ---- Removable devices -------------------------------------------------- */
const USB = {
  id: 'usb',
  label: 'USB & Devices',
  icon: Usb,
  accent: 'text-violet-500',
  primaryField: 'device',
  columns: [
    { key: 'device', label: 'Device', grow: true },
    { key: 'serial', label: 'Serial', mono: true },
    { key: 'vendor', label: 'Vendor / Product', grow: true },
    { key: 'connection', label: 'Event' },
  ],
  fields: {
    device: ['device', 'friendlyname', 'friendly_name', 'devicename', 'description', 'model', 'value'],
    serial: ['serial', 'serialnumber', 'serial_number', 'iserialnumber', 'guid'],
    vendor: ['vendor', 'vendorproduct', 'manufacturer', 'product', 'vid_pid', 'vidpid'],
    connection: ['connection', 'event', 'action', 'kind', 'type'],
  },
  timeAliases: [
    'firstconnected', 'first_connected', 'lastconnected', 'last_connected', 'firstinstall',
    'timestamp', 'time', 'date', 'installdate', 'connected',
  ],
  detectFields: ['device', 'vendor'],
  sources: {
    windows: [
      { key: 'usbstor', name: 'USBSTOR', path: 'SYSTEM hive → …\\Enum\\USBSTOR', mode: 'script', script: USB_WIN_USBSTOR, tool: 'native PowerShell' },
      { key: 'setupapi', name: 'setupapi log', path: 'C:\\Windows\\INF\\setupapi.dev.log', mode: 'file', parser: 'setupapi', accept: '.log,.txt', tool: 'upload the log file' },
    ],
    linux: [
      { key: 'journal', name: 'kernel USB events', path: '/var/log/syslog, journal', mode: 'script', script: USB_LINUX_JOURNAL, tool: 'native journalctl' },
    ],
    macos: [],
  },
}

export const ARTIFACT_CATEGORIES = [EXECUTION, PERSISTENCE, FILE_ACCESS, USB]

/** Returns a category definition from its id. */
export function getArtifactCategoryById(id) {
  return ARTIFACT_CATEGORIES.find((c) => c.id === id) ?? null
}

/** All source keys of a category across every OS (for the data slots). */
export function categorySourceKeys(category) {
  const keys = new Set()
  for (const os of ['windows', 'macos', 'linux']) {
    for (const source of category.sources[os] ?? []) keys.add(source.key)
  }
  return [...keys]
}

/** Initial data for a category: an empty { records, meta } slot per source. */
export function buildDefaultArtifactData(category) {
  const sources = {}
  for (const key of categorySourceKeys(category)) sources[key] = { records: [], meta: null }
  return { sources }
}

/** Map { [categoryId]: data } with every category initialized empty. */
export function buildDefaultArtifactsMap() {
  const map = {}
  for (const category of ARTIFACT_CATEGORIES) map[category.id] = buildDefaultArtifactData(category)
  return map
}

/** Sources available for a category on a given host OS. */
export function artifactSourcesFor(category, osId) {
  return category.sources[osId] ?? []
}

/** Map { [sourceKey]: sourceName } across every OS (first occurrence wins). */
export function sourceNameByKey(category) {
  const map = {}
  for (const os of ['windows', 'macos', 'linux']) {
    for (const source of category.sources[os] ?? []) {
      if (!map[source.key]) map[source.key] = source.name
    }
  }
  return map
}
