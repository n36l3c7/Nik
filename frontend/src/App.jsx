import { Suspense, useCallback, useEffect, useState } from 'react'
import {
  AlertTriangle,
  Download,
  FileText,
  LogOut,
  PanelRight,
  Plus,
  RefreshCw,
  Settings,
  ShieldCheck,
} from 'lucide-react'
import { useAuth } from './context/AuthContext.jsx'
import { useIncidents } from './context/IncidentContext.jsx'
import { ANALYSIS_TABS, getTabById } from './config/tabs.js'
import { AsciiSkull, Button, EmptyState, ErrorBoundary, MicroSkull, Modal } from './components/ui/index.js'
import Sidebar from './components/layout/Sidebar.jsx'
import Header from './components/layout/Header.jsx'
import TabBar from './components/layout/TabBar.jsx'
import TailPanel from './components/layout/TailPanel.jsx'
import IncidentLoadingState from './components/layout/IncidentLoadingState.jsx'
import { isTypingTarget } from './domain/search.js'
import SettingsPanel from './components/settings/SettingsPanel.jsx'
import CommandPalette from './components/search/CommandPalette.jsx'
import ReportDialog from './components/report/ReportDialog.jsx'
import IncidentFields, { EMPTY_INCIDENT_FIELDS, canCreateIncident } from './components/incident/IncidentFields.jsx'
import AddFileDialog from './components/incident/AddFileDialog.jsx'
import { useNavigation } from './context/NavigationContext.jsx'
import { detectFileRoute, readHead } from './domain/fileRouting.js'
import LoginScreen from './components/auth/LoginScreen.jsx'
import FirstRunSetup from './components/auth/FirstRunSetup.jsx'

/*
 * ============================================================================
 * APPLICATION SHELL
 * ============================================================================
 *
 * Boot gate (before auth):
 *   - session probe in flight  → "Connecting…" splash
 *   - backend unreachable      → "Cannot reach the server" card with Retry
 *
 * Auth gate:
 *   - no users at all      → first-run setup (create the first admin)
 *   - users but not signed in → login screen
 *   - signed in            → the main app
 *
 * Layout: fixed sidebar (incident management) + right column with header,
 * analysis tab bar and a scrollable content area.
 */

// Sidebar width bounds. The maximum is a quarter of the viewport (computed at
// drag time); this is the hard floor so the incident list stays usable.
const SIDEBAR_MIN_WIDTH = 240
const SIDEBAR_DEFAULT_WIDTH = 288
const SIDEBAR_WIDTH_KEY = 'nik.sidebarWidth'

/** Clamp a sidebar width to [MIN, 25% of the viewport]. */
function clampSidebarWidth(width) {
  const max = Math.max(SIDEBAR_MIN_WIDTH, Math.round(window.innerWidth / 4))
  return Math.min(Math.max(width, SIDEBAR_MIN_WIDTH), max)
}

/**
 * Draggable divider between the sidebar and the main column. Reports the new
 * width (already clamped) to the parent while the pointer moves.
 */
function SidebarResizer({ onResize }) {
  const onPointerDown = (event) => {
    event.preventDefault()
    const move = (e) => onResize(clampSidebarWidth(e.clientX))
    const up = () => {
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
  }

  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-label="Resize sidebar"
      onPointerDown={onPointerDown}
      className="group relative z-10 w-1 shrink-0 cursor-col-resize bg-transparent hover:bg-accent/30"
      title="Drag to resize the sidebar"
    >
      {/* Wider invisible hit area for easier grabbing. */}
      <span className="absolute inset-y-0 -left-1 -right-1" />
    </div>
  )
}

/** Full-screen boot splash shown while the session probe is in flight. */
function ConnectingScreen() {
  return (
    <div className="flex h-screen items-center justify-center bg-canvas">
      <div className="flex flex-col items-center gap-3">
        <MicroSkull className="text-2xl text-accent" />
        <p role="status" className="text-sm text-fg-muted">
          Connecting…
        </p>
      </div>
    </div>
  )
}

/** Full-screen error card shown when the backend cannot be reached. */
function UnreachableScreen({ error, onRetry }) {
  return (
    <div className="flex h-screen items-center justify-center bg-canvas p-4">
      <div className="w-full max-w-sm border border-line bg-panel p-6 text-center">
        <div className="mb-4 flex justify-center">
          <MicroSkull mood="x" className="text-2xl text-high-fg" />
        </div>
        <h1 className="text-base font-semibold text-fg">Cannot reach the server</h1>
        <p className="mt-1.5 text-sm text-fg-muted">
          The application could not contact the backend API. Check that the service is running, then try again.
        </p>
        {error && <p className="mt-3 break-words bg-canvas px-3 py-2 font-mono text-xs text-fg-muted">{error}</p>}
        <Button icon={RefreshCw} onClick={onRetry} className="mt-5 w-full justify-center">
          Retry
        </Button>
      </div>
    </div>
  )
}

export default function App() {
  const { hasUsers, isAuthenticated, authReady, serverError, retry, logout } = useAuth()
  const {
    activeIncident,
    activeSummary,
    activeLoading,
    activeLoadError,
    retryActiveIncident,
    storageError,
    createIncident,
    whenSaved,
    exportIncident,
    loading,
  } = useIncidents()

  const [activeTabId, setActiveTabId] = useState(ANALYSIS_TABS[0].id)
  // `tail -f` side panel, open or closed per tab (open on Summary by default).
  const [tailOpenByTab, setTailOpenByTab] = useState({ summary: true })
  const tailOpen = Boolean(tailOpenByTab[activeTabId])
  const setTailOpen = (open) => setTailOpenByTab((prev) => ({ ...prev, [activeTabId]: open }))

  // "New incident" modal: ticket ID, short title, severity, host, user, OS.
  const [createOpen, setCreateOpen] = useState(false)
  const [newFields, setNewFields] = useState(EMPTY_INCIDENT_FIELDS)

  // Navigation requests from menus and dialogs (see NavigationContext).
  const navigation = useNavigation()
  const { importInto, clearSearch } = navigation
  useEffect(() => {
    if (navigation.focus) setActiveTabId(navigation.focus.tab)
  }, [navigation.focus])

  // A file dropped anywhere: the overlay while dragging, then the dialog.
  const [dragging, setDragging] = useState(false)
  const [drop, setDrop] = useState(null) // { file, route }
  useEffect(() => {
    if (!isAuthenticated) return undefined
    let depth = 0
    const hasFiles = (event) => Array.from(event.dataTransfer?.types ?? []).includes('Files')
    const onEnter = (event) => {
      if (!hasFiles(event)) return
      depth += 1
      setDragging(true)
    }
    const onLeave = (event) => {
      if (!hasFiles(event)) return
      depth = Math.max(0, depth - 1)
      if (depth === 0) setDragging(false)
    }
    const onOver = (event) => {
      if (hasFiles(event)) event.preventDefault()
    }
    const onDrop = async (event) => {
      if (!hasFiles(event)) return
      depth = 0
      setDragging(false)
      // A drop zone inside a tab (it calls preventDefault) handles its own files.
      if (event.defaultPrevented) return
      event.preventDefault()
      const file = event.dataTransfer.files?.[0]
      if (!file) return
      setDrop({ file, route: detectFileRoute({ name: file.name, head: await readHead(file) }) })
    }
    window.addEventListener('dragenter', onEnter)
    window.addEventListener('dragleave', onLeave)
    window.addEventListener('dragover', onOver)
    window.addEventListener('drop', onDrop)
    return () => {
      window.removeEventListener('dragenter', onEnter)
      window.removeEventListener('dragleave', onLeave)
      window.removeEventListener('dragover', onOver)
      window.removeEventListener('drop', onDrop)
    }
  }, [isAuthenticated])

  // Unified settings panel: a single dialog with sections. `settingsSection`
  // lets the header/sidebar deep-link into Detection rules / Accounts / Audit.
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [settingsSection, setSettingsSection] = useState('detection')
  const openSettings = (section = 'detection') => {
    setSettingsSection(section)
    setSettingsOpen(true)
  }

  // Incident report dialog (preview, PDF/HTML download).
  const [reportOpen, setReportOpen] = useState(false)

  // Global search palette: Ctrl/Cmd+K anywhere, "/" outside text fields.
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [paletteQuery, setPaletteQuery] = useState('')
  useEffect(() => {
    if (!navigation.search) return
    setPaletteQuery(navigation.search.query)
    setPaletteOpen(true)
    clearSearch()
  }, [navigation.search, clearSearch])
  useEffect(() => {
    if (!isAuthenticated) return undefined
    const onKeyDown = (event) => {
      const modifier = event.ctrlKey || event.metaKey
      if (modifier && !event.altKey && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setPaletteOpen((open) => !open)
      } else if (event.key === '/' && !modifier && !isTypingTarget(event.target)) {
        event.preventDefault()
        setPaletteOpen(true)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [isAuthenticated])

  // Resizable sidebar width (persisted, re-clamped on load and on window resize).
  const [sidebarWidth, setSidebarWidth] = useState(() => {
    const stored = Number(localStorage.getItem(SIDEBAR_WIDTH_KEY))
    return Number.isFinite(stored) && stored > 0 ? stored : SIDEBAR_DEFAULT_WIDTH
  })
  const handleSidebarResize = useCallback((width) => {
    setSidebarWidth(width)
    localStorage.setItem(SIDEBAR_WIDTH_KEY, String(width))
  }, [])

  // Keep the sidebar within a quarter of the viewport when the window shrinks.
  useEffect(() => {
    const onResize = () => setSidebarWidth((w) => clampSidebarWidth(w))
    window.addEventListener('resize', onResize)
    // Clamp once on mount too (stored value may exceed the current viewport).
    setSidebarWidth((w) => clampSidebarWidth(w))
    return () => window.removeEventListener('resize', onResize)
  }, [])

  const activeTab = getTabById(activeTabId) ?? ANALYSIS_TABS[0]
  const ActiveTabComponent = activeTab.component

  // ---- Boot gate (session probe / server reachability) ----
  if (!authReady) return <ConnectingScreen />
  if (serverError) return <UnreachableScreen error={serverError} onRetry={retry} />

  // ---- Auth gate ----
  if (!hasUsers) return <FirstRunSetup />
  if (!isAuthenticated) return <LoginScreen />

  const openCreateModal = () => {
    setNewFields(EMPTY_INCIDENT_FIELDS)
    setCreateOpen(true)
  }

  const handleCreateSubmit = (event) => {
    event.preventDefault()
    if (!canCreateIncident(newFields)) return
    createIncident(newFields)
    setCreateOpen(false)
  }

  const handleDropConfirm = async ({ target, fields, tab, params }) => {
    const { file } = drop
    setDrop(null)
    if (target === 'new') {
      const incident = createIncident(fields)
      // Samples and .evtx files go to the server: the incident must exist there first.
      if (!(await whenSaved(incident.id))) return
    }
    importInto(tab, file, params)
  }

  // Palette actions (typed after ">").
  const paletteActions = [
    { id: 'new', label: 'New incident', icon: Plus, run: openCreateModal },
    ...(activeIncident
      ? ANALYSIS_TABS.map((tab) => ({
          id: `tab:${tab.id}`,
          label: `Go to ${tab.label}`,
          icon: tab.icon,
          hint: 'tab',
          run: () => setActiveTabId(tab.id),
        }))
      : []),
    ...(activeIncident
      ? [
          { id: 'report', label: 'Incident report (PDF)', icon: FileText, run: () => setReportOpen(true) },
          {
            id: 'export',
            label: 'Export incident (JSON)',
            icon: Download,
            run: () => exportIncident(activeIncident.id),
          },
          { id: 'tail', label: 'Toggle the tail -f panel', icon: PanelRight, run: () => setTailOpen(!tailOpen) },
        ]
      : []),
    { id: 'settings', label: 'Open settings', icon: Settings, run: () => openSettings('detection') },
    {
      id: 'allowlist',
      label: 'Edit the IOC allowlist',
      icon: ShieldCheck,
      keywords: 'settings indicators',
      run: () => openSettings('allowlist'),
    },
    { id: 'logout', label: 'Sign out', icon: LogOut, run: logout },
  ]

  // ---- Initial async load of incidents from the API ----
  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-canvas">
        <div className="flex flex-col items-center gap-3">
          <MicroSkull className="text-2xl text-accent" />
          <p role="status" className="text-sm text-fg-muted">
            Loading incidents…
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar
        width={sidebarWidth}
        onCreateIncident={openCreateModal}
        onOpenAudit={() => openSettings('audit')}
        onOpenUsers={() => openSettings('accounts')}
        onOpenReport={() => setReportOpen(true)}
      />
      <SidebarResizer onResize={handleSidebarResize} />

      <div className="flex min-w-0 flex-1 flex-col">
        <Header
          onOpenSettings={() => openSettings('detection')}
          onOpenSearch={() => setPaletteOpen(true)}
          onOpenReport={activeIncident ? () => setReportOpen(true) : null}
        />
        <TabBar
          activeTabId={activeTabId}
          onChange={setActiveTabId}
          tailOpen={tailOpen}
          onToggleTail={() => setTailOpen(!tailOpen)}
        />

        {storageError && (
          <div
            role="alert"
            className="flex shrink-0 items-center gap-2 border-b border-high-line bg-high-soft px-6 py-2.5 text-sm text-high-fg"
          >
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span>{storageError}</span>
          </div>
        )}

        <div className="flex min-h-0 flex-1">
          <main className="min-w-0 flex-1 overflow-y-auto p-6">
            {activeIncident ? (
              <Suspense
                fallback={
                  <div aria-busy="true" className="flex flex-col items-center justify-center gap-4 py-16">
                    <AsciiSkull preset="medium" />
                    <p role="status" className="font-mono text-sm text-fg-muted">
                      Loading…
                    </p>
                  </div>
                }
              >
                <ErrorBoundary resetKey={`${activeTabId}:${activeIncident.id}`}>
                  <ActiveTabComponent incident={activeIncident} />
                </ErrorBoundary>
              </Suspense>
            ) : activeLoading ? (
              <IncidentLoadingState name={activeSummary.name} />
            ) : activeLoadError ? (
              <div className="flex h-full items-center justify-center">
                <EmptyState
                  illustration={<AsciiSkull preset="medium" eyes="x" tone="muted" />}
                  title="Unable to load the incident"
                  message={activeLoadError}
                  action={
                    <Button icon={RefreshCw} onClick={retryActiveIncident}>
                      Retry
                    </Button>
                  }
                />
              </div>
            ) : (
              <div className="flex h-full items-center justify-center">
                <EmptyState
                  illustration={<AsciiSkull preset="medium" eyes="closed" tone="muted" />}
                  title="No active incident"
                  message="Create a new incident to get started, or import an existing one from the sidebar."
                  action={
                    <Button icon={Plus} onClick={openCreateModal}>
                      New incident
                    </Button>
                  }
                />
              </div>
            )}
          </main>
          {tailOpen && activeIncident && (
            <TailPanel
              incident={activeIncident}
              onClose={() => setTailOpen(false)}
              className="hidden w-80 shrink-0 lg:flex"
            />
          )}
        </div>
      </div>

      {/* New incident modal */}
      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="New incident"
        maxWidth="max-w-xl"
        footer={
          <>
            <Button variant="secondary" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" form="form-new-incident" disabled={!canCreateIncident(newFields)}>
              Create incident
            </Button>
          </>
        }
      >
        <form id="form-new-incident" onSubmit={handleCreateSubmit} className="space-y-4">
          <p className="text-sm text-fg-muted">
            Fill in at least one of ticket ID, short title, host or user. The name is a label, not a unique id, so
            duplicates are allowed.
          </p>
          <IncidentFields value={newFields} onChange={setNewFields} idPrefix="new" />
        </form>
      </Modal>

      <AddFileDialog
        drop={drop}
        activeIncident={activeIncident}
        onClose={() => setDrop(null)}
        onConfirm={handleDropConfirm}
      />

      {dragging && (
        <div
          aria-hidden="true"
          className="pointer-events-none fixed inset-3 z-[80] flex items-center justify-center border-2 border-dashed border-accent bg-accent-soft/80"
        >
          <p className="font-mono text-lg text-accent-fg">drop the file: Nik finds the right tab</p>
        </div>
      )}

      <ReportDialog
        open={reportOpen && Boolean(activeIncident)}
        onClose={() => setReportOpen(false)}
        incident={activeIncident}
      />

      <CommandPalette
        open={paletteOpen}
        initialQuery={paletteQuery}
        onClose={() => {
          setPaletteOpen(false)
          setPaletteQuery('')
        }}
        actions={paletteActions}
        onOpenTab={setActiveTabId}
      />

      <SettingsPanel
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        section={settingsSection}
        onSectionChange={setSettingsSection}
      />
    </div>
  )
}
