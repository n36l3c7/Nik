/*
 * The sections of the rail and the first screen of each.
 *
 * An entry of the rail always shows the first screen of its section, from
 * wherever it is pressed: from a screen inside the section (a playbook in the
 * editor, a dashboard being edited, a section of Settings) as from another
 * section. Pressed on that first screen it does nothing: it is not a switch
 * that closes what it opened.
 *
 * homeMove() says what pressing an entry must do; App carries it out.
 */

import { ARTIFACTS_ROOT } from './artifactRegistry.js'
import { AUTOMATION_ROOT } from './automationNav.js'
import { DASHBOARDS_ROOT, isDashboardsPath } from './dashboards.js'
import { INCIDENTS_ROOT, isIncidentsPath } from './incidentList.js'
import { LIBRARY_ROOT } from './iocLibrary.js'
import { PLAYGROUND_ROOT } from './playground.js'
import { settingsPath } from './settingsNav.js'
import { TASKS_ROOT, isTasksPath } from './tasks.js'

/** The entries of the rail, from the top, with the permission each needs. The foot holds Settings. */
export const RAIL_SECTIONS = [
  { id: 'dashboards', label: 'Dashboards', permission: 'read' },
  { id: 'incidents', label: 'Incidents', permission: 'read' },
  { id: 'tasks', label: 'My tasks', permission: 'read' },
  { id: 'artifacts', label: 'Artifacts', permission: 'read' },
  { id: 'iocs', label: 'Indicators', permission: 'read' },
  { id: 'automation', label: 'Automations', permission: 'automation.run' },
  { id: 'playground', label: 'Playground', permission: 'automation.run' },
]

/** The section of Settings its entry opens. */
export const SETTINGS_HOME = 'detection'

const pathOnly = (path) => String(path ?? '').split('?')[0]
// The start and /incidents both show the list of incidents.
const isListPath = (path) => path === '/' || isIncidentsPath(path)

/**
 * What pressing the entry of `section` does, given where the person is:
 *
 *   at.path        the address shown
 *   at.panel       the side panel shown: 'artifacts', 'iocs' or null
 *   at.incidentId  the incident that is open (under a page drawn over it too), or null
 *   at.first       { dashboards, tasks }: true when that page shows what a fresh visit shows (the
 *                  address alone cannot tell: both pages go to their first item by themselves)
 *   at.filtered    the list of the artifacts is narrowed by a filter
 *   at.quick       the quick filter of the Indicators ('all' on a fresh visit)
 *
 * Returns null when the first screen of the section is what is shown already; otherwise
 * `{ path, panel }`: the address to go to (null: it stays) and the side panel to show
 * (undefined: as it is). The page is then shown as first opened.
 */
export function homeMove(section, at = {}) {
  const path = pathOnly(at.path)
  const panel = at.panel ?? null
  const go = (home) => (home === path ? null : home)
  switch (section) {
    case 'dashboards':
      return isDashboardsPath(path) && at.first?.dashboards ? null : { path: go(DASHBOARDS_ROOT) }
    case 'tasks':
      return isTasksPath(path) && at.first?.tasks ? null : { path: go(TASKS_ROOT) }
    case 'incidents':
      // The list alone: no side panel beside it.
      if (isListPath(path)) return panel ? { path: null, panel: null } : null
      return { path: INCIDENTS_ROOT, panel: null }
    case 'artifacts':
      // Their page: the list with nothing filtered, and no artifact open beside it.
      if (path === ARTIFACTS_ROOT && !at.filtered) return null
      return { path: go(ARTIFACTS_ROOT), panel: 'artifacts' }
    case 'iocs':
      if (path === LIBRARY_ROOT && panel === 'iocs' && (at.quick ?? 'all') === 'all') return null
      return { path: go(LIBRARY_ROOT), panel: 'iocs' }
    case 'automation': {
      const home = `${AUTOMATION_ROOT}/playbooks`
      return path === home || path === AUTOMATION_ROOT ? null : { path: home }
    }
    case 'playground':
      return path === PLAYGROUND_ROOT ? null : { path: PLAYGROUND_ROOT }
    case 'settings': {
      const home = settingsPath(SETTINGS_HOME)
      return path === home ? null : { path: home }
    }
    default:
      return null
  }
}
