import { Fish, SquareChevronRight, SquareTerminal, Terminal } from 'lucide-react'

/*
 * ============================================================================
 * SHELL REGISTRY — the only file to edit to add a shell
 * ============================================================================
 *
 * The "Command History" tab shows a sub-tab for each shell listed here, in the
 * same way the Browser Forensics tab does per browser. Each shell declares:
 *  - id / label / icon:  identity and entry in the sub-tab bar
 *  - format:             'bash' | 'zsh' | 'fish' | 'psreadline' — the text
 *                        parser used for the history file (see
 *                        services/shellParsers.js). JSON/CSV exports from
 *                        forensic tools are accepted regardless of format.
 *  - accent:             accent color of the sub-tab (Tailwind classes)
 *  - os:                 which host OSes ship this shell — the sub-tab is
 *                        shown when the incident's OS matches (or when data
 *                        was already imported for it)
 *  - timestamps:         short note about whether the format carries times
 *  - source:             the single history FILE the user uploads, with the
 *                        typical path per OS (shown in the "where to find the
 *                        file" note driven by the incident's OS)
 */

export const SHELLS = [
  {
    id: 'bash',
    label: 'Bash',
    icon: Terminal,
    format: 'bash',
    accent: 'text-emerald-500',
    os: ['linux', 'macos'],
    timestamps:
      'Timestamps only exist if HISTTIMEFORMAT was set on the host (lines starting with #<epoch>).',
    source: {
      key: 'history',
      label: '.bash_history',
      icon: Terminal,
      accept: '',
      paths: {
        linux: '~/.bash_history',
        macos: '~/.bash_history',
        windows: 'C:\\Users\\<user>\\.bash_history  (Git Bash / WSL: \\\\wsl$\\<distro>\\home\\<user>\\)',
      },
      hint: 'Plain-text history, one command per line. With HISTTIMEFORMAT set, each command is preceded by a #<epoch> timestamp line.',
    },
  },
  {
    id: 'zsh',
    label: 'Zsh',
    icon: SquareTerminal,
    format: 'zsh',
    accent: 'text-violet-500',
    os: ['linux', 'macos'],
    timestamps:
      'The extended format (": <epoch>:<duration>;command", default on macOS) carries a timestamp per command.',
    source: {
      key: 'history',
      label: '.zsh_history',
      icon: SquareTerminal,
      accept: '',
      paths: {
        linux: '~/.zsh_history',
        macos: '~/.zsh_history',
      },
      hint: 'Zsh history: plain lines or EXTENDED_HISTORY format (": <epoch>:<duration>;command"). macOS default shell since Catalina.',
    },
  },
  {
    id: 'fish',
    label: 'Fish',
    icon: Fish,
    format: 'fish',
    accent: 'text-sky-500',
    os: ['linux', 'macos'],
    timestamps: 'Every command carries a "when:" epoch timestamp.',
    source: {
      key: 'history',
      label: 'fish_history',
      icon: Fish,
      accept: '',
      paths: {
        linux: '~/.local/share/fish/fish_history',
        macos: '~/.local/share/fish/fish_history',
      },
      hint: 'YAML-like history: "- cmd: <command>" entries, each followed by a "when: <epoch>" timestamp.',
    },
  },
  {
    id: 'powershell',
    label: 'PowerShell',
    icon: SquareChevronRight,
    format: 'psreadline',
    accent: 'text-blue-500',
    os: ['windows', 'linux', 'macos'],
    timestamps:
      'PSReadLine history has NO timestamps: correlate with EDR/Event Logs (4104) for the execution time.',
    source: {
      key: 'history',
      label: 'ConsoleHost_history.txt',
      icon: SquareChevronRight,
      accept: '.txt',
      paths: {
        windows:
          '%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt',
        linux: '~/.local/share/powershell/PSReadLine/ConsoleHost_history.txt',
        macos: '~/.local/share/powershell/PSReadLine/ConsoleHost_history.txt',
      },
      hint: 'PSReadLine history: one command per line (multi-line commands continue with a trailing backtick). No timestamps.',
    },
  },
]

/** Returns the definition of a shell from its id. */
export function getShellById(shellId) {
  return SHELLS.find((s) => s.id === shellId) ?? null
}

/** Shells that ship on a given host OS. */
export function shellsForOs(osId) {
  return SHELLS.filter((s) => s.os.includes(osId))
}

/** Initial data structure for a single shell (no commands, no file). */
export function buildDefaultShellData() {
  return { commands: [], meta: { history: null } }
}

/** Map { [shellId]: shellData } with all shells initialized empty. */
export function buildDefaultShellsMap() {
  const map = {}
  for (const shell of SHELLS) map[shell.id] = buildDefaultShellData()
  return map
}
