import { lazy } from 'react'
import {
  Bug,
  Crosshair,
  LayoutDashboard,
  Mail,
  Globe,
  HardDrive,
  ListTree,
  Network,
  ScrollText,
  TerminalSquare,
} from 'lucide-react'
import { buildDefaultBrowsersMap, BROWSERS } from './browsers.js'
import { buildDefaultShellsMap, SHELLS } from './shells.js'
import { buildDefaultArtifactsMap } from './artifacts.js'

/*
 * ============================================================================
 * ANALYSIS TAB REGISTRY — the single file to edit to add a new analysis tab.
 * ============================================================================
 *
 * Each entry describes a tab:
 *  - id:          unique identifier (used to select the tab)
 *  - label:       label shown in the tab bar
 *  - icon:        Lucide icon shown next to the label
 *  - component:   React component (lazy-loaded => automatic code-splitting).
 *                 Receives the `incident` prop (the active incident).
 *  - dataKey:     key under `incident.data` where the tab stores its data
 *  - defaultData: initial data structure for a new incident
 *
 * To add a tab: create the component under src/components/tabs/ and add an
 * entry below. See README.md § "Add a new analysis tab".
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

export const ANALYSIS_TABS = [
  {
    id: 'summary',
    label: 'Summary',
    icon: LayoutDashboard,
    component: SummaryTab,
    dataKey: 'summary',
    defaultData: {},
  },
  {
    id: 'browser',
    label: 'Browser Forensics',
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
    label: 'Command History',
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
  {
    id: 'endpoint',
    label: 'Endpoint Artifacts',
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
    label: 'Event Logs',
    icon: ScrollText,
    component: EventLogsTab,
    dataKey: 'eventlogs',
    // Windows event logs PER CHANNEL (Security, System, PowerShell…): each
    // holds its curated events and the imported file's metadata and coverage.
    // See config/eventLogs.js and utils/eventLogs.js.
    defaultData: {
      channels: {},
    },
  },
  {
    id: 'malware',
    label: 'Malware Analysis',
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
    id: 'mail',
    label: 'Mail Analysis',
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
    id: 'iocs',
    label: 'IOCs',
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
    icon: ListTree,
    component: TimelineTab,
    dataKey: 'timelineView',
    // The Timeline aggregates timestamped events from every other tab; it
    // stores no data of its own (this key just holds view preferences, if any).
    defaultData: {},
  },
  {
    id: 'network',
    label: 'Network Analysis',
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
]

/**
 * Build the `data` structure of a new incident from the registry: each tab
 * contributes its own `defaultData` under its own `dataKey`. This way adding a
 * tab does NOT require changes to IncidentContext.
 */
export function buildDefaultIncidentData() {
  return Object.fromEntries(ANALYSIS_TABS.map((tab) => [tab.dataKey, structuredClone(tab.defaultData)]))
}

/** Return a tab definition from its id. */
export function getTabById(tabId) {
  return ANALYSIS_TABS.find((tab) => tab.id === tabId) ?? null
}
