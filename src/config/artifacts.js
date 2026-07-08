import { CirclePlay, HardDrive, KeyRound, Usb } from 'lucide-react'

/*
 * ============================================================================
 * ENDPOINT ARTIFACT REGISTRY — the only file to edit to add a category
 * ============================================================================
 *
 * The "Endpoint Artifacts" tab shows a sub-tab per category listed here. Each
 * category is a flaggable, searchable table fed by a CSV/JSON export (the
 * format most DFIR tools produce — KAPE, Eric Zimmerman's tools, RegRipper,
 * plaso…). The lenient column mapping accepts many aliases, so exports from
 * different tools drop in without reshaping.
 *
 * Category shape:
 *   - id / label / icon / accent:  identity and sub-tab entry
 *   - primaryField:  record field used as the row title and flag label
 *   - columns:       [{ key, label, mono?, grow? }] shown in the table
 *   - fields:        { fieldKey: [csv/json column aliases] } — lenient mapping
 *   - timeAliases:   aliases for the record timestamp (Unix ms after anyToMs)
 *   - detectFields:  record fields concatenated into the SOC keyword haystack
 *   - sources:       per-OS guidance { windows|macos|linux: [{ name, path, tool }] }
 *                    driven by the incident's host OS
 *   - timestamped:   false when the artifact usually has no reliable time
 *                    (kept out of the super-timeline)
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
    'timestamp', 'time', 'lastmodified', 'date', 'lastrbuntime', 'lastruntime',
  ],
  detectFields: ['name', 'path'],
  timestamped: true,
  sources: {
    windows: [
      { name: 'Prefetch', path: 'C:\\Windows\\Prefetch\\*.pf', tool: 'PECmd (Eric Zimmerman) → CSV' },
      { name: 'Amcache', path: 'C:\\Windows\\AppCompat\\Programs\\Amcache.hve', tool: 'AmcacheParser → CSV' },
      { name: 'ShimCache (AppCompatCache)', path: 'SYSTEM hive → ControlSet\\Control\\Session Manager\\AppCompatCache', tool: 'AppCompatCacheParser → CSV' },
      { name: 'UserAssist', path: 'NTUSER.dat → …\\Explorer\\UserAssist', tool: 'RegRipper / EZ → CSV' },
      { name: 'BAM/DAM', path: 'SYSTEM hive → …\\Services\\bam\\State\\UserSettings', tool: 'RegRipper → CSV' },
    ],
    macos: [
      { name: 'KnowledgeC (app usage)', path: '~/Library/Application Support/Knowledge/knowledgeC.db', tool: 'mac_apt / SQLite → CSV' },
      { name: 'Spotlight / LaunchServices', path: '~/Library/Preferences/com.apple.LaunchServices*', tool: 'mac_apt → CSV' },
    ],
    linux: [
      { name: 'auditd execve', path: '/var/log/audit/audit.log', tool: 'ausearch -m EXECVE → CSV' },
      { name: 'systemd journal', path: 'journalctl _COMM / _EXE', tool: 'journalctl -o json → CSV' },
    ],
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
  timeAliases: [
    'created', 'createddate', 'modified', 'lastmodified', 'timestamp', 'time',
    'registrationdate', 'date', 'lastwrite', 'lastwritetime',
  ],
  detectFields: ['name', 'command', 'location'],
  timestamped: true,
  sources: {
    windows: [
      { name: 'Run / RunOnce keys', path: 'NTUSER.dat & SOFTWARE → …\\CurrentVersion\\Run', tool: 'RegRipper → CSV' },
      { name: 'Scheduled Tasks', path: 'C:\\Windows\\System32\\Tasks\\', tool: 'KAPE / TaskScheduler → CSV' },
      { name: 'Services', path: 'SYSTEM hive → …\\Services', tool: 'RegRipper → CSV' },
      { name: 'Startup folder', path: '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup', tool: 'directory listing → CSV' },
      { name: 'WMI subscriptions', path: 'OBJECTS.DATA', tool: 'PyWMIPersistenceFinder → CSV' },
    ],
    macos: [
      { name: 'LaunchAgents / LaunchDaemons', path: '~/Library/LaunchAgents, /Library/Launch*', tool: 'plist listing → CSV' },
      { name: 'Login items', path: '~/Library/Preferences/com.apple.loginitems*', tool: 'mac_apt → CSV' },
      { name: 'cron', path: '/usr/lib/cron/tabs/', tool: 'listing → CSV' },
    ],
    linux: [
      { name: 'cron', path: '/etc/crontab, /etc/cron.*, /var/spool/cron/', tool: 'listing → CSV' },
      { name: 'systemd units', path: '/etc/systemd/system/, ~/.config/systemd/user/', tool: 'systemctl list-unit-files → CSV' },
      { name: 'shell rc / profile', path: '~/.bashrc, ~/.profile, /etc/rc.local', tool: 'listing → CSV' },
      { name: 'SSH authorized_keys', path: '~/.ssh/authorized_keys', tool: 'listing → CSV' },
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
    target: ['target', 'targetpath', 'target_path', 'path', 'localpath', 'linktarget', 'arguments'],
    kind: ['kind', 'type', 'artifact', 'source', 'sourcetype'],
  },
  timeAliases: [
    'accessed', 'lastaccessed', 'accesstime', 'opened', 'modified', 'lastmodified',
    'timestamp', 'time', 'date', 'targetmodified', 'sourcemodified', 'sourceaccessed',
  ],
  detectFields: ['name', 'target'],
  timestamped: true,
  sources: {
    windows: [
      { name: 'LNK shortcuts', path: '%APPDATA%\\Microsoft\\Windows\\Recent\\', tool: 'LECmd → CSV' },
      { name: 'JumpLists', path: '…\\Recent\\AutomaticDestinations\\', tool: 'JLECmd → CSV' },
      { name: 'ShellBags', path: 'USRCLASS.dat → …\\Shell\\BagMRU', tool: 'ShellBags Explorer → CSV' },
      { name: 'RecentDocs', path: 'NTUSER.dat → …\\Explorer\\RecentDocs', tool: 'RegRipper → CSV' },
    ],
    macos: [
      { name: 'Recent items / sfl', path: '~/Library/Application Support/com.apple.sharedfilelist/', tool: 'sfltool / mac_apt → CSV' },
      { name: 'Finder recent', path: '~/Library/Preferences/com.apple.finder.plist', tool: 'plutil → CSV' },
    ],
    linux: [
      { name: 'GTK recently-used', path: '~/.local/share/recently-used.xbel', tool: 'xbel parse → CSV' },
      { name: 'GTK bookmarks', path: '~/.config/gtk-3.0/bookmarks', tool: 'listing → CSV' },
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
    'lastinsertion', 'lastremoval', 'timestamp', 'time', 'date', 'installdate', 'connected',
  ],
  detectFields: ['device', 'vendor'],
  timestamped: true,
  sources: {
    windows: [
      { name: 'USBSTOR', path: 'SYSTEM hive → …\\Enum\\USBSTOR', tool: 'RegRipper / USBDeviceForensics → CSV' },
      { name: 'setupapi log', path: 'C:\\Windows\\INF\\setupapi.dev.log', tool: 'text parse → CSV' },
      { name: 'MountedDevices', path: 'SYSTEM hive → MountedDevices', tool: 'RegRipper → CSV' },
    ],
    macos: [
      { name: 'IORegistry / system.log', path: '/var/log/system.log', tool: 'ioreg / log show → CSV' },
    ],
    linux: [
      { name: 'kernel USB events', path: '/var/log/syslog, /var/log/messages, journal', tool: 'journalctl -k → CSV' },
    ],
  },
}

export const ARTIFACT_CATEGORIES = [EXECUTION, PERSISTENCE, FILE_ACCESS, USB]

/** Returns a category definition from its id. */
export function getArtifactCategoryById(id) {
  return ARTIFACT_CATEGORIES.find((c) => c.id === id) ?? null
}

/** Initial data for a single category (no records, no imported file). */
export function buildDefaultArtifactData() {
  return { records: [], meta: null }
}

/** Map { [categoryId]: data } with every category initialized empty. */
export function buildDefaultArtifactsMap() {
  const map = {}
  for (const category of ARTIFACT_CATEGORIES) map[category.id] = buildDefaultArtifactData()
  return map
}

/** Per-OS source list for a category (falls back to Windows). */
export function artifactSourcesFor(category, osId) {
  return category.sources?.[osId] ?? category.sources?.windows ?? []
}
