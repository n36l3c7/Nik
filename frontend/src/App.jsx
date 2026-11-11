import { Suspense, useCallback, useEffect, useState } from 'react'
import {
  AlertTriangle,
  Download,
  FileText,
  LogOut,
  Microscope,
  Plus,
  RefreshCw,
  Settings,
  ShieldCheck,
} from 'lucide-react'
import { useAuth } from './context/AuthContext.jsx'
import { useArtifacts } from './context/ArtifactContext.jsx'
import { useIncidents } from './context/IncidentContext.jsx'
import { useToast } from './context/ToastContext.jsx'
import { ANALYSIS_TABS, getTabById } from './config/tabs.js'
import { AsciiSkull, Button, EmptyState, ErrorBoundary, MicroSkull, Modal } from './components/ui/index.js'
import Rail from './components/layout/Rail.jsx'
import Sidebar from './components/layout/Sidebar.jsx'
import Header from './components/layout/Header.jsx'
import TabBar from './components/layout/TabBar.jsx'
import IncidentLoadingState from './components/layout/IncidentLoadingState.jsx'
import { isTypingTarget } from './domain/search.js'
import SettingsPanel from './components/settings/SettingsPanel.jsx'
import CommandPalette from './components/search/CommandPalette.jsx'
import ReportDialog from './components/report/ReportDialog.jsx'
import IncidentFields, { EMPTY_INCIDENT_FIELDS, canCreateIncident } from './components/incident/IncidentFields.jsx'
import AddFileDialog from './components/incident/AddFileDialog.jsx'
import ArtifactPage from './components/artifacts/ArtifactPage.jsx'
import NewAnalysisDialog from './components/artifacts/NewAnalysisDialog.jsx'
import PastePrompt from './components/artifacts/PastePrompt.jsx'
import BackupModal from './components/backup/BackupModal.jsx'
import { kindForTab } from './domain/artifactRegistry.js'
import { recognise } from './domain/pasted.js'
import { useIocLookup } from './context/IocLookupContext.jsx'
import { sha256Hex } from './lib/hash.js'
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
 * Layout: the rail (icons), the side panel it opens (incidents or
 * artifacts, collapsible) and the main column: header, then either the
 * active incident (analysis tab bar + tab) or the artifact opened on its own.
 */

// Sidebar width bounds. The maximum is a quarter of the viewport (computed at
// drag time); this is the hard floor so the incident list stays usable.
const SIDEBAR_MIN_WIDTH = 240
const SIDEBAR_DEFAULT_WIDTH = 288
const SIDEBAR_WIDTH_KEY = 'nik.sidebarWidth'
// The side panel the rail last opened: 'incidents', 'artifacts' or '' (closed).
const PANEL_KEY = 'nik.panel'
// Above this size a file is not hashed in the browser to look it up before the upload.
const LOOKUP_MAX_BYTES = 100 * 1024 * 1024

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
  const { hasUsers, isAuthenticated, authReady, serverError, retry, logout, currentUser } = useAuth()
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
    incidents,
    selectIncident,
    activeIncidentId,
    retryActiveIncident: reloadActiveIncident,
  } = useIncidents()
  const artifacts = useArtifacts()
  const { showToast } = useToast()
  const { openIoc } = useIocLookup()
  // The main area shows an artifact on its own instead of the active incident.
  const artifactOpen = Boolean(artifacts.currentId)

  const [activeTabId, setActiveTabId] = useState(ANALYSIS_TABS[0].id)

  // "New incident" modal: ticket ID, short title, severity, host, user, OS.
  const [createOpen, setCreateOpen] = useState(false)
  const [newFields, setNewFields] = useState(EMPTY_INCIDENT_FIELDS)

  // Side panel chosen on the rail (null = collapsed), remembered across sessions.
  const [panel, setPanelState] = useState(() => {
    const stored = localStorage.getItem(PANEL_KEY)
    return stored === '' ? null : stored === 'artifacts' ? 'artifacts' : 'incidents'
  })
  const setPanel = useCallback((next) => {
    setPanelState(next)
    localStorage.setItem(PANEL_KEY, next ?? '')
  }, [])
  // An artifact opened from a permalink shows its panel.
  useEffect(() => {
    if (artifactOpen) setPanelState((open) => (open === null ? open : 'artifacts'))
  }, [artifactOpen])

  // Leaving an artifact without opening an incident: the URL follows.
  useEffect(() => {
    if (artifactOpen || !window.location.pathname.startsWith('/artifact/')) return
    const path = activeIncidentId ? `/incident/${encodeURIComponent(activeIncidentId)}` : '/'
    window.history.replaceState({}, '', path)
  }, [artifactOpen, activeIncidentId])

  const [backupOpen, setBackupOpen] = useState(false)
  const [analysisOpen, setAnalysisOpen] = useState(false)
  // The artifact a new incident is being created from (linked once it is saved).
  const [seedArtifact, setSeedArtifact] = useState(null)

  // Navigation requests from menus and dialogs (see NavigationContext).
  const navigation = useNavigation()
  const { importInto, clearSearch } = navigation
  useEffect(() => {
    if (navigation.focus) setActiveTabId(navigation.focus.tab)
  }, [navigation.focus])

  /** Open an incident in the main area (leaving an artifact opened on its own). */
  const { closeArtifact } = artifacts
  const openIncident = useCallback(
    (incidentId) => {
      closeArtifact()
      selectIncident(incidentId)
    },
    [closeArtifact, selectIncident],
  )

  /**
   * A file to place (dropped anywhere, or chosen in "New analysis"): detect
   * what it is and whether it was analysed before, then ask where it goes.
   */
  const { lookup } = artifacts
  const placeFile = useCallback(
    async (file, { preferAnalysis = false } = {}) => {
      const route = detectFileRoute({ name: file.name, head: await readHead(file) })
      const analysable = Boolean(kindForTab(route?.tab ?? 'malware'))
      const known = analysable && file.size <= LOOKUP_MAX_BYTES ? await lookup(await sha256Hex(file)) : []
      setDrop({ file, route, known, preferAnalysis })
    },
    [lookup],
  )

  // Text pasted or dragged onto the app: an address or an indicator Nik can act on.
  const [pasted, setPasted] = useState(null) // recognise() result + { raw, known }
  const [pastedBusy, setPastedBusy] = useState(false)
  const [pastedError, setPastedError] = useState(null)
  const offerText = useCallback(
    async (text) => {
      const match = recognise(text)
      if (!match) return
      // A SHA-256 may be a file or an e-mail that was analysed already.
      const known = match.kind === 'sha256' ? ((await lookup(match.value))[0] ?? null) : null
      setPastedError(null)
      setPasted({ ...match, raw: String(text).trim(), known })
    },
    [lookup],
  )
  const dismissPasted = useCallback(() => setPasted(null), [])
  useEffect(() => {
    if (!isAuthenticated) return undefined
    const onPaste = (event) => {
      // In a text field, pasting is just pasting.
      if (isTypingTarget(event.target)) return
      const file = event.clipboardData?.files?.[0]
      if (file) placeFile(file)
      else offerText(event.clipboardData?.getData('text') ?? '')
    }
    window.addEventListener('paste', onPaste)
    return () => window.removeEventListener('paste', onPaste)
  }, [isAuthenticated, placeFile, offerText])

  // A file dropped anywhere: the overlay while dragging, then the dialog.
  const [dragging, setDragging] = useState(false)
  const [drop, setDrop] = useState(null) // { file, route }
  useEffect(() => {
    if (!isAuthenticated) return undefined
    let depth = 0
    const hasFiles = (event) => Array.from(event.dataTransfer?.types ?? []).includes('Files')
    // Selected text dragged onto the app (not into a text field, where it is just text).
    const hasText = (event) =>
      !hasFiles(event) &&
      Array.from(event.dataTransfer?.types ?? []).includes('text/plain') &&
      !isTypingTarget(event.target)
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
      if (hasFiles(event) || hasText(event)) event.preventDefault()
    }
    const onDrop = (event) => {
      if (hasText(event) && !event.defaultPrevented) {
        event.preventDefault()
        offerText(event.dataTransfer.getData('text/plain'))
        return
      }
      if (!hasFiles(event)) return
      depth = 0
      setDragging(false)
      // A drop zone inside a tab (it calls preventDefault) handles its own files.
      if (event.defaultPrevented) return
      event.preventDefault()
      const file = event.dataTransfer.files?.[0]
      if (file) placeFile(file)
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
  }, [isAuthenticated, placeFile, offerText])

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
    setSeedArtifact(null)
    setNewFields(EMPTY_INCIDENT_FIELDS)
    setCreateOpen(true)
  }

  /** "New incident from this" on an artifact: the usual modal, then the link. */
  const openCreateFromArtifact = (artifact) => {
    setSeedArtifact(artifact)
    setNewFields({ ...EMPTY_INCIDENT_FIELDS, title: artifact.name.slice(0, 80) })
    setCreateOpen(true)
  }

  const handleCreateSubmit = (event) => {
    event.preventDefault()
    if (!canCreateIncident(newFields)) return
    const incident = createIncident(newFields)
    setCreateOpen(false)
    if (!seedArtifact) {
      closeArtifact()
      return
    }
    // The incident must exist on the server before the artifact is linked to it.
    const artifact = seedArtifact
    setSeedArtifact(null)
    whenSaved(incident.id)
      .then((saved) => (saved ? artifacts.link(artifact.id, incident.id) : Promise.reject(new Error('not saved'))))
      .then(() => {
        closeArtifact()
        reloadActiveIncident()
        showToast({ message: `${artifact.name} is in the new incident.` })
      })
      .catch((err) => showToast({ message: `The artifact was not linked: ${err.message}` }))
  }

  const handleDropConfirm = async ({ target, fields, tab, params }) => {
    const { file } = drop
    setDrop(null)
    if (target === 'analysis') {
      // On its own: upload it as an artifact and open its page.
      try {
        const artifact = await artifacts.startAnalysis(kindForTab(tab), file)
        setPanel('artifacts')
        artifacts.openArtifact(artifact.id)
      } catch (err) {
        showToast({ message: `${file.name}: ${err.message}` })
      }
      return
    }
    closeArtifact()
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
    {
      id: 'analysis',
      label: 'New analysis (no incident)',
      icon: Microscope,
      keywords: 'artifact file mail upload',
      run: () => setAnalysisOpen(true),
    },
    ...(activeIncident
      ? ANALYSIS_TABS.map((tab) => ({
          id: `tab:${tab.id}`,
          label: `Go to ${tab.label}`,
          icon: tab.icon,
          hint: 'tab',
          run: () => {
            closeArtifact()
            setActiveTabId(tab.id)
          },
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
      <Rail
        panel={panel}
        onPanel={setPanel}
        counts={{
          incidents: incidents.length,
          artifacts: Object.values(artifacts.counts).reduce((sum, n) => sum + n, 0),
        }}
        isAdmin={currentUser?.role === 'admin'}
        onSearch={() => setPaletteOpen(true)}
        onAudit={() => openSettings('audit')}
        onUsers={() => openSettings('accounts')}
        onBackup={() => setBackupOpen(true)}
        onSettings={() => openSettings('detection')}
      />
      {panel && (
        <>
          <Sidebar
            panel={panel}
            width={sidebarWidth}
            onCreateIncident={openCreateModal}
            onNewAnalysis={() => setAnalysisOpen(true)}
            onSelectIncident={openIncident}
            incidentShown={!artifactOpen}
            onOpenReport={() => setReportOpen(true)}
          />
          <SidebarResizer onResize={handleSidebarResize} />
        </>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <Header
          onOpenSearch={() => setPaletteOpen(true)}
          onOpenReport={activeIncident && !artifactOpen ? () => setReportOpen(true) : null}
          artifactView={artifactOpen}
        />
        {!artifactOpen && <TabBar activeTabId={activeTabId} onChange={setActiveTabId} />}

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
            {artifactOpen ? (
              <ArtifactPage onOpenIncident={openIncident} onNewIncident={openCreateFromArtifact} />
            ) : activeIncident ? (
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
                  message="Create an incident to work a case, or analyse a file or an e-mail on its own. You can also drop a file anywhere."
                  action={
                    <div className="flex flex-wrap justify-center gap-2">
                      <Button icon={Plus} onClick={openCreateModal}>
                        New incident
                      </Button>
                      <Button variant="secondary" icon={Microscope} onClick={() => setAnalysisOpen(true)}>
                        New analysis
                      </Button>
                    </div>
                  }
                />
              </div>
            )}
          </main>
        </div>
      </div>

      {/* New incident modal */}
      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title={seedArtifact ? 'New incident from this artifact' : 'New incident'}
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
        onOpenKnown={(artifact) => {
          setDrop(null)
          setPanel('artifacts')
          artifacts.openArtifact(artifact.id)
        }}
      />

      <NewAnalysisDialog
        open={analysisOpen}
        onClose={() => setAnalysisOpen(false)}
        onFile={(file) => {
          setAnalysisOpen(false)
          placeFile(file, { preferAnalysis: true })
        }}
        onUrl={async (url) => {
          // Throws on a refused address: the dialog shows why and stays open.
          const scan = await artifacts.scanUrl(url)
          setAnalysisOpen(false)
          setPanel('artifacts')
          artifacts.openArtifact(scan.artifactId)
        }}
      />

      <PastePrompt
        pasted={pasted}
        busy={pastedBusy}
        error={pastedError}
        onDismiss={dismissPasted}
        onScan={async (url) => {
          setPastedBusy(true)
          setPastedError(null)
          try {
            const scan = await artifacts.scanUrl(url)
            setPasted(null)
            setPanel('artifacts')
            artifacts.openArtifact(scan.artifactId)
          } catch (err) {
            setPastedError(err.message)
          } finally {
            setPastedBusy(false)
          }
        }}
        onSearch={(value) => {
          setPasted(null)
          setPaletteQuery(value)
          setPaletteOpen(true)
        }}
        onLookup={(kind, value) => {
          setPasted(null)
          openIoc(kind, value)
        }}
        onOpenKnown={(artifact) => {
          setPasted(null)
          setPanel('artifacts')
          artifacts.openArtifact(artifact.id)
        }}
      />

      {currentUser?.role === 'admin' && <BackupModal open={backupOpen} onClose={() => setBackupOpen(false)} />}

      {dragging && (
        <div
          aria-hidden="true"
          className="pointer-events-none fixed inset-3 z-[80] flex items-center justify-center border-2 border-dashed border-accent bg-accent-soft/80"
        >
          <p className="font-mono text-lg text-accent-fg">drop the file: Nik finds the right tab</p>
        </div>
      )}

      <ReportDialog
        open={reportOpen && Boolean(activeIncident) && !artifactOpen}
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
        onOpenTab={(tab) => {
          closeArtifact()
          setActiveTabId(tab)
        }}
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
