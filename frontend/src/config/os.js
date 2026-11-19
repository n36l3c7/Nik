import { Apple, LayoutGrid, Terminal } from 'lucide-react'

/*
 * ============================================================================
 * OPERATING SYSTEM REGISTRY — the incident's host OS
 * ============================================================================
 *
 * Every incident is tied to a single host, so it carries an `os` field
 * (windows | macos | linux). The OS drives everything host-specific in the
 * UI: the artifact paths suggested in the Browser Forensics tab, which shells
 * are offered in the Command History tab, and the incident icon shown in the
 * sidebar/header.
 */

export const OS_LIST = [
  {
    id: 'windows',
    label: 'Windows',
    icon: LayoutGrid,
    accent: 'text-info',
  },
  {
    id: 'macos',
    label: 'macOS',
    icon: Apple,
    accent: 'text-fg',
  },
  {
    id: 'linux',
    label: 'Linux',
    icon: Terminal,
    accent: 'text-med',
  },
]

export const DEFAULT_OS = 'windows'

/** Returns the OS definition from its id (null when unknown). */
export function getOsById(osId) {
  return OS_LIST.find((os) => os.id === osId) ?? null
}

/**
 * The OS of an incident as it is kept: one of the three, or '' when none was
 * said. Since 5.3 an incident need not name one; what needs a system to show
 * something (the paths where an artifact is found, the shells there are)
 * falls back to DEFAULT_OS by itself.
 */
export function normalizeOs(value) {
  return getOsById(value) ? value : ''
}
