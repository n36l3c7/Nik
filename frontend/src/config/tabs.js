import { lazy } from 'react'
import {
  Braces,
  Bug,
  Crosshair,
  FolderSearch,
  Globe,
  HardDrive,
  LayoutDashboard,
  ListChecks,
  Link2,
  ListTree,
  Mail,
  MessagesSquare,
  Network,
  ScrollText,
  TerminalSquare,
} from 'lucide-react'
import { buildDefaultBrowsersMap, BROWSERS } from './browsers.js'
import { buildDefaultShellsMap, SHELLS } from './shells.js'
import { buildDefaultArtifactsMap } from './artifacts.js'

/*
 * ============================================================================
 * TAB REGISTRY — the tabs of an incident, and the kinds of evidence under Evidence.
 * ============================================================================
 *
 * Each entry describes a tab:
 *  - id:          unique identifier (used to select the tab)
 *  - label:       label shown in the tab bar
 *  - short:       one-word label the tab bar uses when the full ones do not fit
 *  - icon:        Lucide icon shown next to the label
 *  - group:       tab bar group, in this order: 'overview' (what the incident
 *                 adds up to), 'threats' (mail, samples, network, URLs) and 'host'
 *                 (what was collected on the machine); a thin rule separates
 *                 the groups
 *  - component:   React component (lazy-loaded => automatic code-splitting).
 *                 Receives the `incident` prop (the active incident).
 *  - dataKey:     key under `incident.data` where the tab stores its data
 *                 (left out by a tab that keeps nothing in the incident)
 *  - defaultData: initial data structure for a new incident
 *  - permission:  shown only to the accounts that hold it (every reader
 *                 sees a tab that names none)
 *  - evidence:    true for a KIND OF EVIDENCE (5.3): it is not on the tab bar
 *                 but in the list of the Evidence tab, and its component is
 *                 the page a file of that kind opens in. It is given
 *                 `focus`, the file chosen in that list (null for the whole
 *                 kind), and `evidence` (true), beside `incident`.
 *
 * To add a tab: create the component under src/components/tabs/ and add an
 * entry below, in its group. See README.md § "Add a new analysis tab".
 */

const SummaryTab = lazy(() => import('../components/tabs/summary/SummaryTab.jsx'))
const BrowserAnalysisTab = lazy(() => import('../components/tabs/browser/BrowserAnalysisTab.jsx'))
const CommandHistoryTab = lazy(() => import('../components/tabs/commands/CommandHistoryTab.jsx'))
const EndpointArtifactsTab = lazy(() => import('../components/tabs/endpoint/EndpointArtifactsTab.jsx'))
const EventLogsTab = lazy(() => import('../components/tabs/eventlogs/EventLogsTab.jsx'))
const MalwareAnalysisTab = lazy(() => import('../components/tabs/malware/MalwareAnalysisTab.jsx'))
const MailAnalysisTab = lazy(() => import('../components/tabs/mail/MailAnalysisTab.jsx'))
const IocsTab = lazy(() => import('../components/tabs/iocs/IocsTab.jsx'))
const TimelineTab = lazy(() => import('../components/tabs/timeline/TimelineTab.jsx'))
const NetworkAnalysisTab = lazy(() => import('../components/tabs/network/NetworkAnalysisTab.jsx'))
const UrlAnalysisTab = lazy(() => import('../components/tabs/urls/UrlAnalysisTab.jsx'))
const ContextTab = lazy(() => import('../components/tabs/context/ContextTab.jsx'))
const WarRoomTab = lazy(() => import('../components/tabs/warroom/WarRoomTab.jsx'))
const WorkPlanTab = lazy(() => import('../components/tabs/workplan/WorkPlanTab.jsx'))

export const ANALYSIS_TABS = [
  {
    id: 'summary',
    label: 'Summary',
    short: 'Summary',
    group: 'overview',
    icon: LayoutDashboard,
    component: SummaryTab,
    dataKey: 'summary',
    defaultData: {},
  },
  {
    id: 'war_room',
    label: 'War Room',
    short: 'Room',
    group: 'overview',
    icon: MessagesSquare,
    component: WarRoomTab,
    // The log is the server's: notes stay in the incident, the rest is read when the tab opens.
  },
  {
    id: 'work_plan',
    label: 'Work plan',
    short: 'Plan',
    group: 'overview',
    icon: ListChecks,
    component: WorkPlanTab,
    // What the playbooks of the incident do step by step, and its tasks: read when the tab opens.
  },
  {
    id: 'context',
    label: 'Context',
    short: 'Ctx',
    group: 'overview',
    icon: Braces,
    component: ContextTab,
    // What playbooks read of the incident: the server's, read when the tab opens.
    permission: 'automation.run',
  },
  {
    id: 'iocs',
    label: 'Indicators',
    short: 'IOCs',
    group: 'overview',
    icon: Crosshair,
    component: IocsTab,
    dataKey: 'iocsView',
    // The server indexes the indicators of every tab when the incident is
    // saved (GET /api/incidents/{id}/iocs); this tab stores no data of its own.
    defaultData: {},
  },
  {
    id: 'timeline',
    label: 'Timeline',
    short: 'Timeline',
    group: 'overview',
    icon: ListTree,
    component: TimelineTab,
    dataKey: 'timelineView',
    // The Timeline aggregates timestamped events from every other tab; it
    // stores no data of its own (this key just holds view preferences, if any).
    defaultData: {},
  },
  {
    id: 'evidence',
    label: 'Evidence',
    short: 'Files',
    group: 'overview',
    icon: FolderSearch,
    // Drawn by the page itself (App.jsx): the list of every file, and the kind that opens it.
    component: null,
  },
  {
    id: 'mail',
    evidence: true,
    label: 'Mail Analysis',
    short: 'Mail',
    group: 'threats',
    icon: Mail,
    component: MailAnalysisTab,
    dataKey: 'mail',
    // E-mails live on the server (sample store + `mails` table); the incident
    // keeps light references: [{ sha256, fileName, subject, from, date,
    // verdict, score, importedAt, … }]. The analysis is fetched per message
    // from GET /api/mails/{sha256}.
    defaultData: {
      messages: [],
    },
  },
  {
    id: 'malware',
    evidence: true,
    label: 'Malware Analysis',
    short: 'Malware',
    group: 'threats',
    icon: Bug,
    component: MalwareAnalysisTab,
    dataKey: 'malware',
    // Samples live on the server (sample store + `samples` table); the
    // incident keeps light references: [{ sha256, fileName, size, type,
    // entropy, importedAt, importedBy, … }]. The analysis is fetched per
    // sample from GET /api/samples/{sha256}.
    defaultData: {
      samples: [],
    },
  },
  {
    id: 'network',
    evidence: true,
    label: 'Network Analysis',
    short: 'Network',
    group: 'threats',
    icon: Network,
    component: NetworkAnalysisTab,
    dataKey: 'network',
    // Captures live on the server (sample store + `network_captures`); the
    // incident keeps light references: [{ id, kind: 'pcap' | 'browser',
    // fileName, status, packets, held, beacons, … }]. The packet list, tree
    // and bytes come from POST /api/captures/{id}/rpc (Wireshark's engine).
    defaultData: {
      captures: [],
    },
  },
  {
    id: 'urls',
    evidence: true,
    label: 'URL Analysis',
    short: 'URL',
    group: 'threats',
    icon: Link2,
    component: UrlAnalysisTab,
    dataKey: 'urls',
    // Scans live on the server (`url_scans`); the incident keeps light
    // references: [{ id, url, host, status, verdict, score, scannedAt }].
    // The result is fetched per address from GET /api/urls/{id}.
    defaultData: {
      scans: [],
    },
  },
  {
    id: 'endpoint',
    evidence: true,
    label: 'Endpoint Artifacts',
    short: 'Endpoint',
    group: 'host',
    icon: HardDrive,
    component: EndpointArtifactsTab,
    dataKey: 'endpoint',
    // Endpoint data is organized PER CATEGORY (execution/persistence/
    // fileaccess/usb): each holds its own records array and imported-file
    // metadata. See config/artifacts.js.
    defaultData: {
      categories: buildDefaultArtifactsMap(),
    },
  },
  {
    id: 'eventlogs',
    evidence: true,
    label: 'Event Logs',
    short: 'Events',
    group: 'host',
    icon: ScrollText,
    component: EventLogsTab,
    dataKey: 'eventlogs',
    // Windows event logs PER CHANNEL (Security, System, PowerShell…): each
    // holds its curated events and the imported file's metadata and coverage.
    // See config/eventLogs.js and domain/eventLogs.js.
    defaultData: {
      channels: {},
    },
  },
  {
    id: 'browser',
    evidence: true,
    label: 'Browser Forensics',
    short: 'Browser',
    group: 'host',
    icon: Globe,
    component: BrowserAnalysisTab,
    dataKey: 'browser',
    // Browser data is organized PER BROWSER (Chrome/Firefox/Edge/Brave/Opera):
    // each browser has its own arrays (history, downloads, bookmarks,
    // shortcuts) and imported-file metadata. See config/browsers.js.
    defaultData: {
      activeBrowser: BROWSERS[0].id,
      browsers: buildDefaultBrowsersMap(),
    },
  },
  {
    id: 'commands',
    evidence: true,
    label: 'Command History',
    short: 'Commands',
    group: 'host',
    icon: TerminalSquare,
    component: CommandHistoryTab,
    dataKey: 'commands',
    // Command data is organized PER SHELL (Bash/Zsh/Fish/PowerShell): each
    // shell has its own commands array and imported-file metadata. See
    // config/shells.js.
    defaultData: {
      activeShell: SHELLS[0].id,
      shells: buildDefaultShellsMap(),
    },
  },
]

/**
 * Build the `data` structure of a new incident from the registry: each tab
 * contributes its own `defaultData` under its own `dataKey`. This way adding a
 * tab does NOT require changes to IncidentContext.
 */
export function buildDefaultIncidentData() {
  return Object.fromEntries(
    ANALYSIS_TABS.filter((tab) => tab.dataKey).map((tab) => [tab.dataKey, structuredClone(tab.defaultData)]),
  )
}

/** The tabs an account sees, given its `can(permission)`. */
export const visibleTabs = (can) => ANALYSIS_TABS.filter((tab) => !tab.permission || can(tab.permission))

/** Return a tab definition from its id. */
export function getTabById(tabId) {
  return ANALYSIS_TABS.find((tab) => tab.id === tabId) ?? null
}
