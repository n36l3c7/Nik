import { FileText, LogOut, Search, UserCircle } from 'lucide-react'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useAuth } from '../../context/AuthContext.jsx'
import { getOsById } from '../../config/os.js'
import { formatRelative } from '../../lib/time.js'
import { SeverityTag, StatusTag } from '../ui/index.js'

/*
 * ============================================================================
 * HEADER — what the main area shows, search, current user chip, sign out
 * ============================================================================
 * Settings, audit log, users and backup are on the rail (Rail.jsx).
 *
 * @param {{
 *   onOpenSearch: () => void,
 *   onOpenReport: (() => void) | null,
 *   artifactView?: boolean,   // the main area shows an artifact, not the active incident
 * }} props
 */
export default function Header({ onOpenSearch, onOpenReport, artifactView = false }) {
  const { activeIncident: loadedIncident, activeSummary } = useIncidents()
  // The light summary row is enough for the header while the document loads.
  const activeIncident = loadedIncident ?? activeSummary
  const { currentUser, logout } = useAuth()

  const os = activeIncident ? getOsById(activeIncident.os) : null
  const OsIcon = os?.icon

  // Every control on the right is 36 px tall, so they line up.
  const iconButton =
    'flex h-9 w-9 shrink-0 items-center justify-center border border-line text-fg-muted transition-colors ' +
    'hover:bg-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

  return (
    <header className="flex shrink-0 items-center justify-between gap-4 border-b border-line bg-canvas px-6 py-3">
      {/* Active incident (or an empty-state message) */}
      <div className="min-w-0">
        {artifactView ? (
          <>
            <h1 className="truncate font-mono text-lg font-semibold leading-tight text-fg">artifact analysis</h1>
            <p className="truncate text-xs text-fg-muted">on its own: link it to an incident from the page below</p>
          </>
        ) : activeIncident ? (
          <>
            <h1 className="flex items-center gap-2 truncate font-mono text-lg font-semibold leading-tight text-fg">
              {OsIcon && <OsIcon className={`h-4 w-4 shrink-0 ${os.accent}`} aria-label={os.label} />}
              <span className="truncate">{activeIncident.name}</span>
              <SeverityTag severity={activeIncident.severity} />
              <StatusTag status={activeIncident.status} />
            </h1>
            <p className="truncate text-xs text-fg-muted">
              {[
                os?.label,
                (activeIncident.ticketId || activeIncident.title) &&
                  [activeIncident.host, activeIncident.username].filter(Boolean).join(' / '),
                activeIncident.assignee && `assigned to ${activeIncident.assignee}`,
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
          className="hidden h-9 items-center gap-2 border border-line px-2.5 font-mono text-xs text-fg-muted transition-colors hover:bg-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent md:inline-flex"
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
          <div
            className="hidden h-9 items-center gap-2 border border-line px-2.5 sm:flex"
            title={`Signed in as ${currentUser.username} (${currentUser.role})`}
          >
            <UserCircle className="h-4 w-4 shrink-0 text-fg-muted" aria-hidden="true" />
            <p className="max-w-40 truncate font-mono text-xs text-fg">
              {currentUser.username} <span className="capitalize text-fg-muted">· {currentUser.role}</span>
            </p>
          </div>
        )}

        <button type="button" onClick={logout} aria-label="Sign out" title="Sign out" className={iconButton}>
          <LogOut className="h-4 w-4" />
        </button>
      </div>
    </header>
  )
}
