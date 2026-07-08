import { lazy } from 'react'
import { LayoutDashboard, Globe, Network, HardDrive } from 'lucide-react'
import { buildDefaultBrowsersMap, BROWSERS } from './browsers.js'

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
const NetworkLogsTab = lazy(() => import('../components/tabs/NetworkLogsTab.jsx'))
const EndpointArtifactsTab = lazy(
  () => import('../components/tabs/EndpointArtifactsTab.jsx'),
)

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
    id: 'network',
    label: 'Network Logs',
    icon: Network,
    component: NetworkLogsTab,
    dataKey: 'network',
    defaultData: {},
  },
  {
    id: 'endpoint',
    label: 'Endpoint Artifacts',
    icon: HardDrive,
    component: EndpointArtifactsTab,
    dataKey: 'endpoint',
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
