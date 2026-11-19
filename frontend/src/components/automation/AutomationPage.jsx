import { Suspense, lazy, useCallback, useEffect, useRef, useState } from 'react'
import { AlertTriangle, X } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { useAutomation } from '../../context/AutomationContext.jsx'
import { api } from '../../services/api.js'
import { visibleAreas } from '../../domain/automationNav.js'
import { useLayer } from '../../lib/layers.js'
import { Button, ErrorBoundary } from '../ui/index.js'
import PlaybookPage from './PlaybookPage.jsx'
import PlaybooksPage from './PlaybooksPage.jsx'
import ApprovalsPage from './ApprovalsPage.jsx'
import RunPage from './RunPage.jsx'
import RunsPage from './RunsPage.jsx'
import ScriptsPage from './ScriptsPage.jsx'

// The script editor brings CodeMirror with it: loaded when a script is opened.
const ScriptPage = lazy(() => import('./ScriptPage.jsx'))

/*
 * ============================================================================
 * AUTOMATIONS — a page next to the rail, with an address per screen
 * ============================================================================
 *
 * Like Settings, the area takes the whole space next to the rail and what
 * was open under it (an incident, an artifact) is there again when it is
 * left. App owns the address (domain/automationNav.js): `route` is what it
 * read from /automation/…, `onNavigate` goes somewhere else in the area and
 * `onClose` leaves it.
 *
 * This file is loaded on first use, with the canvas library it needs.
 */

/**
 * @param {{
 *   route: { area: string, id: string | null, tab: string | null },
 *   onNavigate: (area: string, id?: string | null, tab?: string | null, options?: { replace?: boolean }) => void,
 *   onClose: () => void,
 *   onOpenSettings: (section: string) => void,
 *   onOpenIncident: (id: string) => void,
 * }} props
 */
export default function AutomationPage({ route, onNavigate, onClose, onOpenSettings, onOpenIncident }) {
  const { can } = useAuth()
  const { state, setState, waiting } = useAutomation()
  const areas = visibleAreas(can)
  const [playbooks, setPlaybooks] = useState(null)
  const [error, setError] = useState(null)

  // The shortcuts of what is under the page stand down; Escape is left to what is open inside it.
  const ref = useRef(null)
  useLayer(ref, { open: true, onClose: () => {}, trap: false, page: true })

  const reload = useCallback(async () => {
    try {
      const found = await api.get('/automation/playbooks')
      setPlaybooks(found.playbooks)
      setState({ enabled: Boolean(found.enabled), workerAlive: Boolean(found.workerAlive) })
      setError(null)
    } catch (failure) {
      setError(failure.message)
    }
  }, [setState])
  useEffect(() => {
    reload()
  }, [reload])

  const area = areas.find((item) => item.id === route.area) ?? areas[0]

  return (
    <section
      ref={ref}
      aria-label="Automations"
      tabIndex={-1}
      className="flex min-w-0 flex-1 flex-col bg-canvas outline-none"
    >
      <header className="flex h-14 shrink-0 items-center justify-between gap-3 border-b border-line bg-panel px-6">
        <div className="flex min-w-0 items-center gap-4">
          <h1 className="text-sm font-semibold text-fg">Automations</h1>
          {areas.length > 1 && (
            <nav aria-label="Automations" className="flex gap-1">
              {areas.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  aria-current={item.id === area?.id ? 'page' : undefined}
                  onClick={() => onNavigate(item.id)}
                  className={[
                    'px-2.5 py-1 text-sm font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                    item.id === area?.id ? 'bg-accent-soft text-accent' : 'text-fg-muted hover:bg-canvas hover:text-fg',
                  ].join(' ')}
                >
                  {item.label}
                  {item.id === 'approvals' && waiting > 0 && (
                    <span className="ml-1.5 bg-med-line px-1 font-mono text-[11px] text-canvas">
                      {waiting}
                      <span className="sr-only"> waiting</span>
                    </span>
                  )}
                </button>
              ))}
            </nav>
          )}
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close automations"
          title="Close automations"
          className="p-1.5 text-fg-muted transition-colors hover:bg-canvas hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>
      </header>

      {state && (!state.enabled || !state.workerAlive) && (
        <div
          role="alert"
          className="flex shrink-0 flex-wrap items-center gap-2 border-b border-med-line bg-med-soft px-6 py-2 text-sm text-med-fg"
        >
          <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden="true" />
          <span className="min-w-0 flex-1">
            {!state.enabled
              ? 'Automation is stopped: no playbook starts and no step is taken until an admin starts it again.'
              : 'The automation worker is not answering: playbooks will start when it is back. Check the “automation” container.'}
          </span>
          {!state.enabled && can('admin') && (
            <Button size="xs" variant="secondary" onClick={() => onOpenSettings('automationSwitch')}>
              Open the switch
            </Button>
          )}
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-y-auto">
        <ErrorBoundary resetKey={`${route.area}:${route.id}:${route.tab}:${route.branch ?? ''}`}>
          {area?.id === 'playbooks' && route.id ? (
            <PlaybookPage
              // A branch is another canvas: the page starts again, and what was not saved is sent first.
              key={`${route.id}:${route.branch ?? ''}`}
              id={route.id}
              branchId={route.branch ?? null}
              playbooks={playbooks ?? []}
              onOpenPlaybook={(playbookId, branch = null, options = {}) =>
                onNavigate('playbooks', playbookId, null, { ...options, branch })
              }
              tab={route.tab ?? 'canvas'}
              onTab={(tab) => onNavigate('playbooks', route.id, tab, { replace: true })}
              onBack={() => onNavigate('playbooks')}
              onDeleted={() => {
                reload()
                onNavigate('playbooks', null, null, { replace: true })
              }}
              onChanged={reload}
              onOpenRun={(runId) => onNavigate('runs', runId)}
              onOpenIncident={onOpenIncident}
            />
          ) : area?.id === 'scripts' && route.id ? (
            <Suspense
              fallback={
                <p role="status" className="p-6 font-mono text-sm text-fg-muted">
                  Loading the editor…
                </p>
              }
            >
              <ScriptPage
                key={route.id}
                id={route.id}
                onBack={() => onNavigate('scripts')}
                onOpenPlaybooks={() => onNavigate('playbooks')}
              />
            </Suspense>
          ) : area?.id === 'scripts' ? (
            <ScriptsPage onOpen={(scriptId) => onNavigate('scripts', scriptId)} />
          ) : area?.id === 'runs' && route.id ? (
            <RunPage
              key={route.id}
              id={route.id}
              onBack={() => onNavigate('runs')}
              // A debug run of a branch goes back to the branch it ran.
              onOpenPlaybook={(playbookId, branch = null) => onNavigate('playbooks', playbookId, null, { branch })}
              onOpenIncident={onOpenIncident}
            />
          ) : area?.id === 'runs' ? (
            <RunsPage
              playbooks={playbooks ?? []}
              onOpenRun={(runId) => onNavigate('runs', runId)}
              onOpenIncident={onOpenIncident}
            />
          ) : area?.id === 'approvals' ? (
            <ApprovalsPage onOpenRun={(runId) => onNavigate('runs', runId)} />
          ) : (
            <PlaybooksPage
              playbooks={playbooks}
              error={error}
              onOpen={(id, tab = null, branch = null) => onNavigate('playbooks', id, tab, { branch })}
              onReload={reload}
            />
          )}
        </ErrorBoundary>
      </div>
    </section>
  )
}
