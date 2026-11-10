import { FileText, LogOut, Search, Settings, UserCircle } from 'lucide-react'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useAuth } from '../../context/AuthContext.jsx'
import { getOsById } from '../../config/os.js'
import { formatRelative } from '../../lib/time.js'
import { SeverityTag } from '../ui/index.js'

/*
 * ============================================================================
 * HEADER — active incident, current user chip, sign out, settings
 * ============================================================================
 * @param {{ onOpenSettings: () => void, onOpenSearch: () => void, onOpenReport: (() => void) | null }} props
 */
export default function Header({ onOpenSettings, onOpenSearch, onOpenReport }) {
  const { activeIncident: loadedIncident, activeSummary } = useIncidents()
  // The light summary row is enough for the header while the document loads.
  const activeIncident = loadedIncident ?? activeSummary
  const { currentUser, logout } = useAuth()

  const os = activeIncident ? getOsById(activeIncident.os) : null
  const OsIcon = os?.icon

  // Shared styling for the square icon buttons on the right.
  const iconButton =
    'border border-line p-2 text-fg-muted transition-colors hover:bg-raised hover:text-fg ' +
    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

  return (
    <header className="flex shrink-0 items-center justify-between gap-4 border-b border-line bg-canvas px-6 py-3">
      {/* Active incident (or an empty-state message) */}
      <div className="min-w-0">
        {activeIncident ? (
          <>
            <h1 className="flex items-center gap-2 truncate font-mono text-lg font-semibold leading-tight text-fg">
              {OsIcon && <OsIcon className={`h-4 w-4 shrink-0 ${os.accent}`} aria-label={os.label} />}
              <span className="truncate">{activeIncident.name}</span>
              <SeverityTag severity={activeIncident.severity} />
            </h1>
            <p className="truncate text-xs text-fg-muted">
              {[
                os?.label,
                (activeIncident.ticketId || activeIncident.title) &&
                  [activeIncident.host, activeIncident.username].filter(Boolean).join(' / '),
                `updated ${formatRelative(activeIncident.updatedAt)}`,
              ]
                .filter(Boolean)
                .join(' · ')}
            </p>
          </>
        ) : (
          <h1 className="truncate font-mono text-lg font-semibold text-fg-muted">no incident selected</h1>
        )}
      </div>

      {/* Search + current user chip + sign out + settings */}
      <div className="flex shrink-0 items-center gap-2">
        <button
          type="button"
          onClick={onOpenSearch}
          aria-label="Search"
          title="Search incidents, indicators, samples and events (Ctrl/Cmd+K or /)"
          className="hidden items-center gap-2 border border-line px-2.5 py-1.5 font-mono text-xs text-fg-muted transition-colors hover:bg-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent md:inline-flex"
        >
          <Search className="h-3.5 w-3.5" />
          <span>search…</span>
          <kbd className="border border-line px-1 text-[10px] text-fg-subtle">ctrl k</kbd>
        </button>
        {onOpenReport && (
          <button
            type="button"
            onClick={onOpenReport}
            aria-label="Incident report"
            title="Incident report (preview, PDF, HTML)"
            className={iconButton}
          >
            <FileText className="h-4 w-4" />
          </button>
        )}

        {currentUser && (
          <div className="hidden items-center gap-2 border border-line px-2.5 py-1.5 sm:flex">
            <UserCircle className="h-5 w-5 shrink-0 text-fg-muted" aria-hidden="true" />
            <div className="min-w-0 leading-tight">
              <p className="truncate font-mono text-xs text-fg">{currentUser.username}</p>
              <p className="truncate text-[11px] capitalize text-fg-muted">{currentUser.role}</p>
            </div>
          </div>
        )}

        <button type="button" onClick={logout} aria-label="Sign out" title="Sign out" className={iconButton}>
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
      </div>
    </header>
  )
}
