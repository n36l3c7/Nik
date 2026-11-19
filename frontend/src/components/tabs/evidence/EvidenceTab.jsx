import { Suspense, useEffect, useMemo, useState } from 'react'
import { FolderOpen, FolderSearch, List } from 'lucide-react'
import { evidenceGroups, firstFile } from '../../../domain/evidence.js'
import { AsciiSkull, EmptyState, ErrorBoundary } from '../../ui/index.js'
import ResizeHandle, { useResizablePane } from '../../ui/ResizeHandle.jsx'
import { useObjectMenu } from '../../menu/useObjectMenu.js'

/*
 * ============================================================================
 * EVIDENCE — the files of the incident, one list at the side, one page
 * ============================================================================
 *
 * What were eight tabs (Mail, Malware, Network, URL, Endpoint, Event logs,
 * Browser, Commands) is one: at the side, every file of the incident under
 * its kind; in the middle, the page that kind of file opens in, the same as
 * before.
 *
 *   - a file (an e-mail, a sample, a capture, an address) opens alone, in the
 *     viewer of its kind;
 *   - the name of a kind opens the whole of that kind as it was: its own list
 *     (above the file, so the file keeps the width of the page), where files
 *     are added and removed, and, for what was collected on the machine, its
 *     page.
 *
 * A file dropped anywhere in the window is added as before.
 */

// The colour of what an analysis concluded, as the badges of the artifacts use them: "clean" has none
// (no detection is not a clean bill).
const VERDICT_DOTS = { high: 'bg-high', phishing: 'bg-high', medium: 'bg-med', suspicious: 'bg-med' }

const ROW =
  'flex w-full items-baseline gap-2 px-3 py-1 text-left text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent'

/**
 * @param {{
 *   incident: object,
 *   kinds: object[],                      // the kinds of evidence this incident shows, in order (config/tabs.js)
 *   kind: object | null,                  // the kind on screen; null for the list alone
 *   onKind: (id: string) => void,         // show a kind (the address follows)
 * }} props
 */
export default function EvidenceTab({ incident, kinds, kind, onKind }) {
  const pane = useResizablePane('incident.evidence', { initial: 260, min: 200, max: 480 })
  const [query, setQuery] = useState('')
  const menu = useObjectMenu()
  // The file opened alone, kind by kind; a kind with none here shows the whole of itself.
  const [chosen, setChosen] = useState({})
  useEffect(() => setChosen({}), [incident.id])

  const groups = useMemo(() => evidenceGroups(kinds, incident, query), [kinds, incident, query])
  const every = useMemo(() => evidenceGroups(kinds, incident), [kinds, incident])

  // Nothing was asked: the first file there is.
  const first = useMemo(() => firstFile(every), [every])
  const shownKind = kind ?? kinds.find((item) => item.id === first?.kind) ?? null
  const fallback = !kind && first?.key ? first.key : null
  const group = every.find((item) => item.id === shownKind?.id) ?? null
  const wanted = shownKind ? (chosen[shownKind.id] ?? fallback) : null
  // A file that is no longer there (removed, another incident) is not asked for.
  const focus = wanted && group?.items.some((item) => item.key === wanted) ? wanted : null
  const Viewer = shownKind?.component ?? null

  const open = (kindId, key) => {
    setChosen((before) => ({ ...before, [kindId]: key }))
    onKind(kindId)
  }

  return (
    <div className="flex min-h-[420px] flex-col gap-4 md:flex-row md:gap-0">
      <nav
        aria-label="Evidence"
        style={pane.style}
        className="flex max-h-72 w-full shrink-0 flex-col border border-line bg-panel md:max-h-none md:w-[var(--pane-w)] md:self-start"
      >
        <div className="border-b border-line-soft p-2">
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Find a file…"
            aria-label="Find a file of the incident"
            autoComplete="off"
            className="w-full border border-line bg-canvas px-2 py-1 text-xs text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          />
        </div>
        <ul className="min-h-0 flex-1 overflow-y-auto py-1">
          {groups.length === 0 && (
            <li role="status" className="px-3 py-2 text-xs text-fg-muted">
              No file matches “{query.trim()}”.
            </li>
          )}
          {groups.map((item) => {
            const Icon = item.icon
            const here = item.id === shownKind?.id
            return (
              <li key={item.id}>
                <button
                  type="button"
                  aria-label={item.label}
                  aria-current={here && !focus ? 'page' : undefined}
                  title={
                    item.files
                      ? `${item.label}: the whole list, where files are added and removed`
                      : `${item.label}: what was collected`
                  }
                  onClick={() => open(item.id, null)}
                  className={`${ROW} font-mono ${here ? 'text-fg' : 'text-fg-muted hover:text-fg'} ${here && !focus ? 'bg-raised' : ''}`}
                >
                  <Icon className="h-3.5 w-3.5 shrink-0 self-center" aria-hidden="true" />
                  <span className="min-w-0 flex-1 truncate">{item.label}</span>
                  <span className={`shrink-0 text-[10px] ${item.count ? 'text-fg-muted' : 'text-fg-subtle'}`}>
                    {item.count || '—'}
                  </span>
                </button>
                {item.items.length > 0 && (
                  <ul aria-label={`Files of ${item.label}`}>
                    {item.items.map((file) => {
                      const on = here && focus === file.key
                      return (
                        <li key={file.key}>
                          <button
                            type="button"
                            aria-current={on ? 'page' : undefined}
                            title={[file.name, file.detail].filter(Boolean).join(' · ')}
                            onClick={() => open(item.id, file.key)}
                            onContextMenu={(event) =>
                              menu(event, {
                                title: file.name,
                                actions: [
                                  { label: 'Open', icon: FolderOpen, onSelect: () => open(item.id, file.key) },
                                  {
                                    label: `Open in the list of ${item.label}`,
                                    icon: List,
                                    onSelect: () => open(item.id, null),
                                  },
                                ],
                                copy: [
                                  { label: 'Copy the name', text: file.name },
                                  file.detail && { label: 'Copy the detail', text: file.detail },
                                ],
                              })
                            }
                            className={`${ROW} pl-8 ${on ? 'bg-accent-soft text-fg' : 'text-fg-muted hover:bg-raised hover:text-fg'}`}
                          >
                            <span
                              aria-hidden="true"
                              className={`h-1.5 w-1.5 shrink-0 self-center ${VERDICT_DOTS[file.verdict] ?? 'bg-line'}`}
                            />
                            <span className="min-w-0 flex-1 truncate">{file.name}</span>
                          </button>
                        </li>
                      )
                    })}
                  </ul>
                )}
              </li>
            )
          })}
        </ul>
        <p className="border-t border-line-soft px-3 py-2 text-[11px] leading-snug text-fg-muted">
          Drop a file anywhere in the window to add it. The name of a kind opens its whole list.
        </p>
      </nav>
      <ResizeHandle {...pane.handle} label="Resize the list of evidence" className="hidden md:block" />
      <div className="min-w-0 flex-1 md:pl-4">
        {Viewer ? (
          <Suspense
            fallback={
              <p role="status" className="font-mono text-sm text-fg-muted">
                Loading…
              </p>
            }
          >
            <ErrorBoundary resetKey={`${incident.id}:${shownKind.id}:${focus ?? ''}`}>
              <Viewer incident={incident} focus={focus} evidence />
            </ErrorBoundary>
          </Suspense>
        ) : (
          <EmptyState
            illustration={<AsciiSkull preset="medium" tone="muted" />}
            icon={FolderSearch}
            title="No evidence yet"
            message="Drop a file anywhere in the window (an e-mail, a suspicious file, a capture, an export of browser history, event logs), or choose a kind at the side to add one there."
          />
        )}
      </div>
    </div>
  )
}
