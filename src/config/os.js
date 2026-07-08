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
    accent: 'text-sky-500',
  },
  {
    id: 'macos',
    label: 'macOS',
    icon: Apple,
    accent: 'text-slate-500 dark:text-slate-300',
  },
  {
    id: 'linux',
    label: 'Linux',
    icon: Terminal,
    accent: 'text-amber-500',
  },
]

export const DEFAULT_OS = 'windows'

/** Returns the OS definition from its id (null when unknown). */
export function getOsById(osId) {
  return OS_LIST.find((os) => os.id === osId) ?? null
}

/** Coerce an arbitrary value to a valid OS id (legacy incidents → windows). */
export function normalizeOs(value) {
  return getOsById(value) ? value : DEFAULT_OS
}
