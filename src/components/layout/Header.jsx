import { FolderOpen, LogOut, Moon, Settings, Sun, UserCircle } from 'lucide-react'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useAuth } from '../../context/AuthContext.jsx'
import { useTheme } from '../../context/ThemeContext.jsx'
import { formatRelative } from '../../utils/time.js'

/*
 * ============================================================================
 * HEADER — active incident, current user chip, sign out, settings, theme
 * ============================================================================
 * @param {{ onOpenSettings: () => void }} props
 */
export default function Header({ onOpenSettings }) {
  const { activeIncident } = useIncidents()
  const { currentUser, logout } = useAuth()
  const { theme, toggleTheme } = useTheme()

  const isDark = theme === 'dark'

  // Shared styling for the square icon buttons on the right.
  const iconButton =
    'rounded-lg border border-slate-200 p-2 text-slate-500 transition-colors ' +
    'hover:bg-slate-50 hover:text-slate-700 focus-visible:outline-none ' +
    'focus-visible:ring-2 focus-visible:ring-cyan-500 dark:border-slate-800 ' +
    'dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-200'

  return (
    <header className="flex shrink-0 items-center justify-between gap-4 border-b border-slate-200 bg-white px-6 py-3.5 dark:border-slate-800 dark:bg-slate-900">
      {/* Active incident (or an empty-state message) */}
      <div className="flex min-w-0 items-center gap-3">
        <FolderOpen className="h-5 w-5 shrink-0 text-cyan-600 dark:text-cyan-400" />
        {activeIncident ? (
          <div className="min-w-0">
            <h1 className="truncate text-lg font-semibold leading-tight text-slate-900 dark:text-white">
              {activeIncident.name}
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              updated {formatRelative(activeIncident.updatedAt)}
            </p>
          </div>
        ) : (
          <h1 className="truncate text-lg font-semibold text-slate-500 dark:text-slate-400">
            No incident selected
          </h1>
        )}
      </div>

      {/* Current user chip + sign out + settings + theme toggle */}
      <div className="flex shrink-0 items-center gap-3">
        {currentUser && (
          <div className="hidden items-center gap-2 rounded-lg border border-slate-200 px-2.5 py-1.5 sm:flex dark:border-slate-800">
            <UserCircle className="h-5 w-5 shrink-0 text-slate-400 dark:text-slate-500" />
            <div className="min-w-0 leading-tight">
              <p className="truncate text-xs font-medium text-slate-700 dark:text-slate-200">
                {currentUser.username}
              </p>
              <p className="truncate text-[11px] capitalize text-slate-500 dark:text-slate-400">
                {currentUser.role}
              </p>
            </div>
          </div>
        )}

        <button
          type="button"
          onClick={logout}
          aria-label="Sign out"
          title="Sign out"
          className={iconButton}
        >
          <LogOut className="h-4 w-4" />
        </button>

        <button
          type="button"
          onClick={onOpenSettings}
          aria-label="Open platform settings"
          title="Settings (detection rules, business hours)"
          className={iconButton}
        >
          <Settings className="h-4 w-4" />
        </button>

        <button
          type="button"
          onClick={toggleTheme}
          aria-label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
          title={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
          className={iconButton}
        >
          {/* Sun in dark mode (to switch to light), moon in light mode */}
          {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </button>
      </div>
    </header>
  )
}
