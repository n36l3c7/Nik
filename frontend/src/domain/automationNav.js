/*
 * The Automations area and its addresses.
 *
 *   /automation/playbooks                    the playbooks
 *   /automation/playbooks/<id>               one playbook: its canvas
 *   /automation/playbooks/<id>/<tab>         … its runs, versions or settings
 *   /automation/playbooks/<id>/branches/<b>  … one of its branches, on the canvas
 *   /automation/scripts[/<id>]               the scripts, one script
 *   /automation/runs[/<id>]                  every run, one run
 *   /automation/approvals                    what waits for an answer
 *
 * Like Settings, the area is a page drawn next to the rail: the incident or
 * the artifact under it stays as it is.
 */

export const AUTOMATION_ROOT = '/automation'

/** The areas, in the order of the tabs, with the permission each needs. */
export const AUTOMATION_AREAS = [
  { id: 'playbooks', label: 'Playbooks', permission: 'automation.run' },
  { id: 'scripts', label: 'Scripts', permission: 'automation.edit' },
  { id: 'runs', label: 'Runs', permission: 'automation.run' },
  { id: 'approvals', label: 'Approvals', permission: 'automation.run' },
]

export const PLAYBOOK_TABS = ['canvas', 'runs', 'versions', 'settings']

export const isAutomationPath = (pathname) => /^\/automation(\/|$)/.test(String(pathname ?? ''))

/**
 * What a path asks for: null when it is not the Automations area; otherwise
 * `{ area, id, tab }` (`id` and `tab` null where the address names none), with
 * `branch` when the address is the one of a branch of a playbook.
 */
export function automationFromPath(pathname) {
  const path = String(pathname ?? '').split('?')[0]
  if (!isAutomationPath(path)) return null
  const [, , area, rawId, rawTab, rawBranch] = path.replace(/\/+$/, '').split('/')
  const known = AUTOMATION_AREAS.find((item) => item.id === area)
  if (!known) return { area: 'playbooks', id: null, tab: null }
  let id
  try {
    id = rawId ? decodeURIComponent(rawId) : null
  } catch {
    id = null
  }
  if (known.id === 'approvals') return { area: 'approvals', id: null, tab: null }
  const tab = known.id === 'playbooks' && id ? (PLAYBOOK_TABS.includes(rawTab) ? rawTab : 'canvas') : null
  if (known.id === 'playbooks' && id && rawTab === 'branches' && rawBranch) {
    try {
      return { area: known.id, id, tab, branch: decodeURIComponent(rawBranch) }
    } catch {
      /* not an address of a branch: the playbook itself */
    }
  }
  return { area: known.id, id, tab }
}

/** The address of an area, of one of its objects, of a tab of a playbook, of a branch on its canvas. */
export function automationPath(area = 'playbooks', id = null, tab = null, branch = null) {
  let path = `${AUTOMATION_ROOT}/${area}`
  if (id) path += `/${encodeURIComponent(id)}`
  if (id && tab && tab !== 'canvas') path += `/${tab}`
  else if (id && branch && area === 'playbooks') path += `/branches/${encodeURIComponent(branch)}`
  return path
}

/** The areas an account can open, given its `can(permission)`. */
export const visibleAreas = (can) => AUTOMATION_AREAS.filter((area) => can(area.permission))
