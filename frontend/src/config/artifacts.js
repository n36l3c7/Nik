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
 * The "Endpoint Artifacts" tab shows a selector item per category; the columns of each
 * are in domain/endpointPage.js. Each category is a
 * flaggable table fed by one or more SOURCES; the table shows the union of
 * every source's records, tagged by which source produced them.
 *
 * A source is imported in one of two ways (never a third-party tool):
 *   - mode 'file'   → upload the EXISTING raw file from the host; the worker's
 *                     `endpoint` parser turns it into records. Used when the
 *                     data already lives in a plain text/XML/log/SQLite file.
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
 *   sources        { windows|macos|linux: [source] } driven by the host OS
 *
 * Source shape (per OS):
 *   key            unique within the category (the `<id>` of the source name `<os>.<category>.<id>`)
 *   name           label shown in the collection list
 *   path           where the data lives (file path or registry location)
 *   mode           'file' | 'script'
 *   script         (script) { lang, code } shown with copy/download
 *   tool           short label describing the method
 */

/* ---- Program execution -------------------------------------------------- */
const EXECUTION = {
  id: 'execution',
  label: 'Program Execution',
  icon: CirclePlay,
  accent: 'text-accent',
  sources: {
    windows: [
      {
        key: 'bam',
        name: 'BAM/DAM last execution',
        path: 'SYSTEM hive → …\\Services\\bam\\State\\UserSettings',
        mode: 'script',
        script: EXEC_WIN_BAM,
        tool: 'native PowerShell',
      },
    ],
    macos: [
      {
        key: 'knowledgec',
        name: 'KnowledgeC app usage',
        path: '~/Library/Application Support/Knowledge/knowledgeC.db',
        mode: 'file',
        tool: 'SQLite (read by the server)',
      },
    ],
    linux: [],
  },
}

/* ---- Persistence -------------------------------------------------------- */
const PERSISTENCE = {
  id: 'persistence',
  label: 'Persistence',
  icon: KeyRound,
  accent: 'text-med',
  sources: {
    windows: [
      {
        key: 'runkeys',
        name: 'Run / RunOnce keys',
        path: 'NTUSER.dat & SOFTWARE → …\\CurrentVersion\\Run',
        mode: 'script',
        script: PERS_WIN_RUN,
        tool: 'native PowerShell',
      },
      {
        key: 'tasks',
        name: 'Scheduled Tasks',
        path: 'C:\\Windows\\System32\\Tasks\\',
        mode: 'script',
        script: PERS_WIN_TASKS,
        tool: 'native PowerShell',
      },
      {
        key: 'services',
        name: 'Services',
        path: 'SYSTEM hive → …\\Services',
        mode: 'script',
        script: PERS_WIN_SERVICES,
        tool: 'native PowerShell',
      },
      {
        key: 'startup',
        name: 'Startup folder',
        path: '%APPDATA%\\…\\Start Menu\\Programs\\Startup',
        mode: 'script',
        script: PERS_WIN_STARTUP,
        tool: 'native PowerShell',
      },
      {
        key: 'wmi',
        name: 'WMI subscriptions',
        path: 'root\\Subscription',
        mode: 'script',
        script: PERS_WIN_WMI,
        tool: 'native PowerShell',
      },
    ],
    linux: [
      {
        key: 'cron',
        name: 'cron',
        path: '/etc/crontab, /etc/cron.d/*, /var/spool/cron/*',
        mode: 'file',
        tool: 'upload the cron file',
      },
      {
        key: 'sshkeys',
        name: 'SSH authorized_keys',
        path: '~/.ssh/authorized_keys',
        mode: 'file',
        tool: 'upload the file',
      },
      {
        key: 'rc',
        name: 'shell rc / profile',
        path: '~/.bashrc, ~/.profile, /etc/rc.local',
        mode: 'file',
        tool: 'upload the file',
      },
      {
        key: 'systemd',
        name: 'enabled systemd units',
        path: '/etc/systemd/system/, ~/.config/systemd/user/',
        mode: 'script',
        script: PERS_LINUX_SYSTEMD,
        tool: 'native systemctl',
      },
    ],
    macos: [
      {
        key: 'launch',
        name: 'LaunchAgent / LaunchDaemon',
        path: '~/Library/LaunchAgents/*.plist, /Library/Launch*',
        mode: 'file',
        tool: 'upload the .plist (XML)',
      },
      {
        key: 'cron',
        name: 'cron',
        path: '/usr/lib/cron/tabs/*',
        mode: 'file',
        tool: 'upload the cron file',
      },
    ],
  },
}

/* ---- File & folder access ---------------------------------------------- */
const FILE_ACCESS = {
  id: 'fileaccess',
  label: 'File & Folder Access',
  icon: HardDrive,
  accent: 'text-info',
  // Windows/macOS file-access forensics (LNK, JumpLists, ShellBags, sfl) can
  // only be parsed with third-party tools, so no custom source is offered.
  sources: {
    windows: [],
    macos: [],
    linux: [
      {
        key: 'recent',
        name: 'GTK recently-used',
        path: '~/.local/share/recently-used.xbel',
        mode: 'file',
        tool: 'upload the file (XML)',
      },
    ],
  },
}

/* ---- Removable devices -------------------------------------------------- */
const USB = {
  id: 'usb',
  label: 'USB & Devices',
  icon: Usb,
  accent: 'text-violet',
  sources: {
    windows: [
      {
        key: 'usbstor',
        name: 'USBSTOR',
        path: 'SYSTEM hive → …\\Enum\\USBSTOR',
        mode: 'script',
        script: USB_WIN_USBSTOR,
        tool: 'native PowerShell',
      },
      {
        key: 'setupapi',
        name: 'setupapi log',
        path: 'C:\\Windows\\INF\\setupapi.dev.log',
        mode: 'file',
        tool: 'upload the log file',
      },
    ],
    linux: [
      {
        key: 'journal',
        name: 'kernel USB events',
        path: '/var/log/syslog, journal',
        mode: 'script',
        script: USB_LINUX_JOURNAL,
        tool: 'native journalctl',
      },
    ],
    macos: [],
  },
}

export const ARTIFACT_CATEGORIES = [EXECUTION, PERSISTENCE, FILE_ACCESS, USB]

/** Returns a category definition from its id. */
export function getArtifactCategoryById(id) {
  return ARTIFACT_CATEGORIES.find((c) => c.id === id) ?? null
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
