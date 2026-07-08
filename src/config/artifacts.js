import { CirclePlay, HardDrive, KeyRound, Usb } from 'lucide-react'
import {
  EXEC_WIN_PREFETCH,
  EXEC_WIN_AMCACHE,
  EXEC_WIN_SHIMCACHE,
  EXEC_WIN_USERASSIST,
  EXEC_WIN_BAM,
  EXEC_LINUX_AUDITD,
  EXEC_MAC_KNOWLEDGEC,
  PERS_WIN_RUN,
  PERS_WIN_TASKS,
  PERS_WIN_SERVICES,
  PERS_WIN_STARTUP,
  PERS_WIN_WMI,
  PERS_LINUX_CRON,
  PERS_LINUX_SYSTEMD,
  PERS_LINUX_SSHKEYS,
  PERS_LINUX_RC,
  PERS_MAC_LAUNCH,
  PERS_MAC_CRON,
  FA_WIN_LNK,
  FA_WIN_JUMPLISTS,
  FA_WIN_SHELLBAGS,
  FA_WIN_RECENTDOCS,
  FA_LINUX_RECENT,
  FA_MAC_RECENT,
  USB_WIN_USBSTOR,
  USB_WIN_SETUPAPI,
  USB_LINUX_JOURNAL,
  USB_MAC_PROFILER,
} from './collectionScripts.js'

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
    name: ['name', 'program', 'executable', 'executablename', 'application', 'applicationname', 'filename', 'sourcefilename', 'process', 'value'],
    path: ['path', 'fullpath', 'full_path', 'file_path', 'sourcefilename', 'image', 'devicepath', 'programpath'],
    runCount: ['runcount', 'run_count', 'count', 'executioncount', 'timesexecuted'],
    source: ['source', 'artifact', 'sourcetype', 'type', 'hive'],
  },
  timeAliases: [
    'lastrun', 'last_run', 'lastexecuted', 'last_executed', 'runtime', 'executiontime',
    'timestamp', 'time', 'lastmodified', 'date', 'lastruntime', 'filekeylastwritetimestamp',
  ],
  detectFields: ['name', 'path'],
  timestamped: true,
  sources: {
    windows: [
      { name: 'Prefetch', path: 'C:\\Windows\\Prefetch\\*.pf', tool: 'PECmd (Eric Zimmerman) → CSV', script: EXEC_WIN_PREFETCH },
      { name: 'Amcache', path: 'C:\\Windows\\AppCompat\\Programs\\Amcache.hve', tool: 'AmcacheParser → CSV', script: EXEC_WIN_AMCACHE },
      { name: 'ShimCache (AppCompatCache)', path: 'SYSTEM hive → ControlSet\\Control\\Session Manager\\AppCompatCache', tool: 'AppCompatCacheParser → CSV', script: EXEC_WIN_SHIMCACHE },
      { name: 'UserAssist', path: 'NTUSER.dat → …\\Explorer\\UserAssist', tool: 'RECmd / RegRipper → CSV', script: EXEC_WIN_USERASSIST },
      { name: 'BAM/DAM', path: 'SYSTEM hive → …\\Services\\bam\\State\\UserSettings', tool: 'native PowerShell → CSV', script: EXEC_WIN_BAM },
    ],
    macos: [
      { name: 'KnowledgeC (app usage)', path: '~/Library/Application Support/Knowledge/knowledgeC.db', tool: 'sqlite3 → CSV', script: EXEC_MAC_KNOWLEDGEC },
    ],
    linux: [
      { name: 'auditd execve', path: '/var/log/audit/audit.log', tool: 'ausearch -m EXECVE → CSV', script: EXEC_LINUX_AUDITD },
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
      { name: 'Run / RunOnce keys', path: 'NTUSER.dat & SOFTWARE → …\\CurrentVersion\\Run', tool: 'native PowerShell → CSV', script: PERS_WIN_RUN },
      { name: 'Scheduled Tasks', path: 'C:\\Windows\\System32\\Tasks\\', tool: 'native PowerShell → CSV', script: PERS_WIN_TASKS },
      { name: 'Services', path: 'SYSTEM hive → …\\Services', tool: 'native PowerShell → CSV', script: PERS_WIN_SERVICES },
      { name: 'Startup folder', path: '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup', tool: 'native PowerShell → CSV', script: PERS_WIN_STARTUP },
      { name: 'WMI subscriptions', path: 'root\\Subscription', tool: 'native PowerShell → CSV', script: PERS_WIN_WMI },
    ],
    macos: [
      { name: 'LaunchAgents / LaunchDaemons', path: '~/Library/LaunchAgents, /Library/Launch*', tool: 'shell script → CSV', script: PERS_MAC_LAUNCH },
      { name: 'cron', path: '/usr/lib/cron/tabs/', tool: 'shell script → CSV', script: PERS_MAC_CRON },
    ],
    linux: [
      { name: 'cron', path: '/etc/crontab, /etc/cron.*, /var/spool/cron/', tool: 'shell script → CSV', script: PERS_LINUX_CRON },
      { name: 'systemd units', path: '/etc/systemd/system/, ~/.config/systemd/user/', tool: 'shell script → CSV', script: PERS_LINUX_SYSTEMD },
      { name: 'shell rc / profile', path: '~/.bashrc, ~/.profile, /etc/rc.local', tool: 'shell script → CSV', script: PERS_LINUX_RC },
      { name: 'SSH authorized_keys', path: '~/.ssh/authorized_keys', tool: 'shell script → CSV', script: PERS_LINUX_SSHKEYS },
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
      { name: 'LNK shortcuts', path: '%APPDATA%\\Microsoft\\Windows\\Recent\\', tool: 'LECmd → CSV', script: FA_WIN_LNK },
      { name: 'JumpLists', path: '…\\Recent\\AutomaticDestinations\\', tool: 'JLECmd → CSV', script: FA_WIN_JUMPLISTS },
      { name: 'ShellBags', path: 'USRCLASS.dat → …\\Shell\\BagMRU', tool: 'SBECmd → CSV', script: FA_WIN_SHELLBAGS },
      { name: 'RecentDocs', path: 'NTUSER.dat → …\\Explorer\\RecentDocs', tool: 'RECmd / RegRipper → CSV', script: FA_WIN_RECENTDOCS },
    ],
    macos: [
      { name: 'Finder recent', path: '~/Library/Preferences/com.apple.finder.plist', tool: 'defaults read → txt', script: FA_MAC_RECENT },
    ],
    linux: [
      { name: 'GTK recently-used', path: '~/.local/share/recently-used.xbel', tool: 'shell script → CSV', script: FA_LINUX_RECENT },
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
      { name: 'USBSTOR', path: 'SYSTEM hive → …\\Enum\\USBSTOR', tool: 'native PowerShell → CSV', script: USB_WIN_USBSTOR },
      { name: 'setupapi log', path: 'C:\\Windows\\INF\\setupapi.dev.log', tool: 'native PowerShell → CSV', script: USB_WIN_SETUPAPI },
    ],
    macos: [
      { name: 'IORegistry / system_profiler', path: 'system_profiler SPUSBDataType', tool: 'system_profiler → txt', script: USB_MAC_PROFILER },
    ],
    linux: [
      { name: 'kernel USB events', path: '/var/log/syslog, journal', tool: 'shell script → CSV', script: USB_LINUX_JOURNAL },
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
