import { lazy } from 'react'
import { LayoutDashboard, Globe, HardDrive, ListTree, Network, TerminalSquare } from 'lucide-react'
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
const BrowserAnalysisTab = lazy(
  () => import('../components/tabs/browser/BrowserAnalysisTab.jsx'),
)
const CommandHistoryTab = lazy(
  () => import('../components/tabs/commands/CommandHistoryTab.jsx'),
)
const EndpointArtifactsTab = lazy(
  () => import('../components/tabs/endpoint/EndpointArtifactsTab.jsx'),
)
const TimelineTab = lazy(() => import('../components/tabs/timeline/TimelineTab.jsx'))
const NetworkLogsTab = lazy(() => import('../components/tabs/NetworkLogsTab.jsx'))

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
    label: 'Network Logs',
    icon: Network,
    component: NetworkLogsTab,
    dataKey: 'network',
    defaultData: {},
  },
]

/**
 * Build the `data` structure of a new incident from the registry: each tab
 * contributes its own `defaultData` under its own `dataKey`. This way adding a
 * tab does NOT require changes to IncidentContext.
 */
export function buildDefaultIncidentData() {
  return Object.fromEntries(
    ANALYSIS_TABS.map((tab) => [tab.dataKey, structuredClone(tab.defaultData)]),
  )
}

/** Return a tab definition from its id. */
export function getTabById(tabId) {
  return ANALYSIS_TABS.find((tab) => tab.id === tabId) ?? null
}
