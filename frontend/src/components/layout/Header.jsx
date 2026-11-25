import { FileText, Keyboard } from 'lucide-react'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useAuth } from '../../context/AuthContext.jsx'
import { useNavigation } from '../../context/NavigationContext.jsx'
import { firstPartialSource, partialPill, tabOfKind } from '../../domain/evidence.js'
import { useEvidenceSummary } from '../../lib/useEvidenceSummary.js'
import { evidence } from '../../services/api.js'
import { getOsById } from '../../config/os.js'
import { formatRelative } from '../../lib/time.js'
import { SeverityTag, StatusTag } from '../ui/index.js'
import IncidentTags from '../incident/IncidentTags.jsx'
import IncidentNumber from '../ui/IncidentNumber.jsx'
import ConnectorLogo from '../ui/ConnectorLogo.jsx'
import { ArchiveControl } from '../incident/ArchiveControl.jsx'
import SearchBar from './SearchBar.jsx'

/*
 * ============================================================================
 * HEADER — what the main area shows, the search bar, the shortcuts and the report
 * ============================================================================
 * Settings, audit log, users and backup are on the rail (Rail.jsx). The search
 * bar is in the middle, as in the header of every page (SearchBar.jsx): the
 * name of what is open is cut short, and the bar shrinks, before the controls
 * on the right are pushed out.
 *
 * @param {{
 *   onOpenShortcuts: () => void,
 *   onOpenReport: (() => void) | null,
 *   artifactView?: boolean,   // the main area shows the artifacts, not the active incident
 *   artifactChosen?: boolean, // …and one of them is open
 *   libraryView?: boolean,    // the main area shows the Indicators page
 * }} props
 */
export default function Header({
  onOpenShortcuts,
  onOpenReport,
  artifactView = false,
  artifactChosen = true,
  libraryView = false,
}) {
  const { activeIncident: loadedIncident, activeSummary } = useIncidents()
  // The light summary row is enough for the header while the document loads.
  const activeIncident = loadedIncident ?? activeSummary
  const { currentUser, can } = useAuth()

  const { goTo } = useNavigation()
  // How many files of host evidence were read in part and nobody looked at (the server counts them).
  const { summary } = useEvidenceSummary(loadedIncident?.id, { enabled: Boolean(loadedIncident) && can('read') })
  const partial = partialPill(summary)
  const openPartial = async () => {
    // The first such file: its kind says which page holds it.
    const kinds = Object.entries(summary?.kinds ?? {}).filter(([, held]) => held.partial > 0)
    for (const [kind] of kinds) {
      try {
        const { sources } = await evidence.sources(loadedIncident.id, { kind })
        const found = firstPartialSource(sources)
        if (found) {
          goTo(tabOfKind(kind) ?? 'evidence', { params: { sourceId: found.id } })
          return
        }
      } catch {
        // The page of the kind opens anyway: its list says which file it is.
      }
      goTo(tabOfKind(kind) ?? 'evidence')
      return
    }
  }

  const os = activeIncident ? getOsById(activeIncident.os) : null
  const OsIcon = os?.icon

  // Every control on the right is 36 px tall, so they line up.
  const iconButton =
    'flex h-9 w-9 shrink-0 items-center justify-center border border-line text-fg-muted transition-colors ' +
    'hover:bg-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

  return (
    <header className="@container flex shrink-0 items-center justify-between gap-4 border-b border-line bg-canvas px-6 py-3">
      {/* Active incident (or an empty-state message) */}
      {/* On a narrow header the name keeps its room and the bar sits beside it; on a wide one both sides
          grow alike and the bar is in the middle. */}
      <div className="min-w-[40%] flex-1 basis-0 @5xl:min-w-0">
        {libraryView ? (
          <>
            <h1 className="truncate font-mono text-lg font-semibold leading-tight text-fg">indicators</h1>
            <p className="truncate text-xs text-fg-muted">the library of every incident and analyst</p>
          </>
        ) : artifactView ? (
          <>
            <h1 className="truncate font-mono text-lg font-semibold leading-tight text-fg">
              {artifactChosen ? 'artifact analysis' : 'artifacts'}
            </h1>
            <p className="truncate text-xs text-fg-muted">
              {artifactChosen
                ? 'on its own: link it to an incident from the page below'
                : 'the files, e-mails, captures and addresses analysed so far'}
            </p>
          </>
        ) : activeIncident ? (
          <>
            <h1 className="flex items-center gap-2 truncate font-mono text-lg font-semibold leading-tight text-fg">
              {OsIcon && <OsIcon className={`h-4 w-4 shrink-0 ${os.accent}`} aria-label={os.label} />}
              <IncidentNumber number={activeIncident.number} />
              <ConnectorLogo source={activeIncident.source} className="h-5 w-5" />
              <span className="truncate">{activeIncident.name}</span>
              <SeverityTag severity={activeIncident.severity} />
              <StatusTag status={activeIncident.status} />
              {partial && (
                <button
                  type="button"
                  onClick={openPartial}
                  title="Some files were read only in part: open the first one"
                  className="shrink-0 border border-med-line bg-med-soft px-2 py-0.5 font-sans text-xs font-medium text-med-fg hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  {partial}
                </button>
              )}
            </h1>
            {/* Its tags, changed where they are read (the field `labels`; the light row carries them too). */}
            <IncidentTags
              incidentId={activeIncident.id}
              tags={loadedIncident ? loadedIncident.fields?.labels : activeIncident.tags}
              className="mt-1"
            />
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

      <SearchBar />

      {/* Shortcuts, the report, what the account may do */}
      <div className="flex flex-1 basis-0 items-center justify-end gap-2">
        <button
          type="button"
          onClick={onOpenShortcuts}
          aria-label="Keyboard shortcuts"
          title="Keyboard shortcuts (?)"
          className={`hidden lg:flex ${iconButton}`}
        >
          <Keyboard className="h-4 w-4" />
        </button>
        {loadedIncident && !libraryView && !artifactView && <ArchiveControl incident={loadedIncident} />}
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

        {loadedIncident?.archivedAt && !libraryView && !artifactView && (
          <span
            className="hidden h-9 items-center border border-med-line bg-med-soft px-2.5 font-mono text-xs text-med-fg sm:flex"
            title="An archived incident is read-only: take it out of the archive to work on it."
          >
            archived
          </span>
        )}
        {currentUser && can('read') && !can('write') && (
          <span
            className="hidden h-9 items-center border border-line px-2.5 font-mono text-xs text-fg-muted sm:flex"
            title="Your roles let you read, not change: ask an admin for the Analyst role to work on incidents."
          >
            read-only
          </span>
        )}
      </div>
    </header>
  )
}
