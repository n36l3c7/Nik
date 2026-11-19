import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from 'react'
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
  Workflow,
} from 'lucide-react'
import { useAuth } from './context/AuthContext.jsx'
import { useArtifacts } from './context/ArtifactContext.jsx'
import { useIncidents } from './context/IncidentContext.jsx'
import { useToast } from './context/ToastContext.jsx'
import { ANALYSIS_TABS, getTabById, visibleTabs } from './config/tabs.js'
import { AsciiSkull, Button, EmptyState, ErrorBoundary, MicroSkull, Modal } from './components/ui/index.js'
import Rail from './components/layout/Rail.jsx'
import Sidebar from './components/layout/Sidebar.jsx'
import Header from './components/layout/Header.jsx'
import TabBar from './components/layout/TabBar.jsx'
import IncidentLoadingState from './components/layout/IncidentLoadingState.jsx'
import { isTypingTarget } from './domain/search.js'
import SettingsPage from './components/settings/SettingsPage.jsx'
import CommandPalette from './components/search/CommandPalette.jsx'
import ReportDialog from './components/report/ReportDialog.jsx'
import IncidentFields, { EMPTY_INCIDENT_FIELDS, canCreateIncident } from './components/incident/IncidentFields.jsx'
import AddFileDialog from './components/incident/AddFileDialog.jsx'
import ArtifactPage from './components/artifacts/ArtifactPage.jsx'
import IocLibraryPage from './components/iocs/IocLibraryPage.jsx'
import { useIocLibrary } from './context/IocLibraryContext.jsx'
import { isIndicatorList, isLibraryPath, isSeveralValues, mayHoldIndicators } from './domain/iocLibrary.js'
import { api } from './services/api.js'
import { currentPath, onLocationChange, setPath } from './lib/location.js'
import { settingsFromPath, settingsPath } from './domain/settingsNav.js'
import { automationFromPath, automationPath } from './domain/automationNav.js'
import { tasksFromPath, tasksPath } from './domain/tasks.js'
import { dashboardsFromPath, dashboardsPath, landingDashboard } from './domain/dashboards.js'
import { PLAYGROUND_ROOT, isPlaygroundPath } from './domain/playground.js'
import { useTasks } from './context/TasksContext.jsx'
import NotificationsDialog from './components/tasks/NotificationsDialog.jsx'
import { mailboxFormatOf } from './domain/mailbox.js'
import NewAnalysisDialog from './components/artifacts/NewAnalysisDialog.jsx'
import PastePrompt from './components/artifacts/PastePrompt.jsx'
import KeyboardShortcuts from './components/keyboard/KeyboardShortcuts.jsx'
import { kindForTab } from './domain/artifactRegistry.js'
import { recognise } from './domain/pasted.js'
import { useIocLookup } from './context/IocLookupContext.jsx'
import { sha256Hex } from './lib/hash.js'
import { useNavigation } from './context/NavigationContext.jsx'
import { detectFileRoute, readHead } from './domain/fileRouting.js'
import LoginScreen from './components/auth/LoginScreen.jsx'
import SessionExpiredDialog from './components/auth/SessionExpiredDialog.jsx'
import FirstRunSetup from './components/auth/FirstRunSetup.jsx'
import { useAutomation } from './context/AutomationContext.jsx'
import ApprovalBanner from './components/automation/ApprovalBanner.jsx'
import RunPlaybookDialog from './components/automation/RunPlaybookDialog.jsx'
import CloseIncidentDialog from './components/fields/CloseIncidentDialog.jsx'
import IncidentPanel from './components/fields/IncidentPanel.jsx'
import { useFields } from './context/FieldsContext.jsx'
import { orderTabs, typeOf } from './domain/fields.js'
import { EVIDENCE_TAB, resolveTab } from './domain/evidence.js'
import ResizeHandle, { useResizablePane } from './components/ui/ResizeHandle.jsx'

// The Automations area comes with the canvas library: loaded when first opened.
const AutomationPage = lazy(() => import('./components/automation/AutomationPage.jsx'))
const TasksPage = lazy(() => import('./components/tasks/TasksPage.jsx'))
const EvidenceTab = lazy(() => import('./components/tabs/evidence/EvidenceTab.jsx'))
const DashboardsPage = lazy(() => import('./components/dashboards/DashboardsPage.jsx'))
const PlaygroundPage = lazy(() => import('./components/playground/PlaygroundPage.jsx'))

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
 * The Settings page (/settings/…) and the Automations area (/automation/…)
 * take the whole area next to the rail; what was open under them is there
 * again when they are left.
 */

// Sidebar width bounds. The maximum is a quarter of the viewport (computed at
// drag time); this is the hard floor so the incident list stays usable.
const SIDEBAR_MIN_WIDTH = 240
const SIDEBAR_DEFAULT_WIDTH = 288
const SIDEBAR_WIDTH_KEY = 'nik.sidebarWidth'
// The side panel the rail last opened: 'incidents', 'artifacts' or '' (closed).
const PANEL_KEY = 'nik.panel'
// The tab last opened on an incident of each type: nik.tab.<type id>.
const TAB_KEY = 'nik.tab'
// Above this size a file is not hashed in the browser to look it up before the upload.
const LOOKUP_MAX_BYTES = 100 * 1024 * 1024

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
  const { hasUsers, isAuthenticated, authReady, serverError, retry, logout, can } = useAuth()
  // What the roles of the signed-in account allow: the shell shows what it can use.
  const canRead = can('read')
  const canWrite = can('write')
  const {
    activeIncident,
    activeSummary,
    activeLoading,
    activeLoadError,
    retryActiveIncident,
    storageError,
    unsavedChanges,
    retrySave,
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
  // …or the Indicators page, which takes the main area in the same way.
  const library = useIocLibrary()
  const libraryOpen = Boolean(library.view)

  const [activeTabId, setActiveTabId] = useState(ANALYSIS_TABS[0].id)

  // "New incident" modal: ticket ID, short title, severity, host, user, OS.
  const [createOpen, setCreateOpen] = useState(false)
  const [newFields, setNewFields] = useState(EMPTY_INCIDENT_FIELDS)

  // Side panel chosen on the rail (null = collapsed), remembered across sessions.
  const [panel, setPanelState] = useState(() => {
    const stored = localStorage.getItem(PANEL_KEY)
    return stored === '' ? null : ['artifacts', 'iocs'].includes(stored) ? stored : 'incidents'
  })
  const setPanel = useCallback((next) => {
    setPanelState(next)
    localStorage.setItem(PANEL_KEY, next ?? '')
  }, [])
  // An artifact opened from a permalink shows its panel.
  useEffect(() => {
    if (artifactOpen) setPanelState((open) => (open === null ? open : 'artifacts'))
  }, [artifactOpen])

  // The library and an artifact share the main area: opening one leaves the other.
  const { closeView: closeLibrary, view: libraryView } = library
  useEffect(() => {
    if (artifacts.currentId) closeLibrary()
  }, [artifacts.currentId, closeLibrary])
  useEffect(() => {
    if (!libraryView) return
    artifacts.closeArtifact()
    setPanelState((open) => (open === null ? open : 'iocs'))
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only when the view changes
  }, [libraryView])
  useEffect(() => {
    if (libraryOpen || artifactOpen || !isLibraryPath(window.location.pathname)) return
    const path = activeIncidentId ? `/incident/${encodeURIComponent(activeIncidentId)}` : '/'
    setPath(path, { replace: true })
  }, [libraryOpen, artifactOpen, activeIncidentId])

  // Leaving an artifact without opening an incident: the URL follows.
  useEffect(() => {
    if (artifactOpen || !window.location.pathname.startsWith('/artifact/')) return
    const path = activeIncidentId ? `/incident/${encodeURIComponent(activeIncidentId)}` : '/'
    setPath(path, { replace: true })
  }, [artifactOpen, activeIncidentId])

  const [analysisOpen, setAnalysisOpen] = useState(false)
  // The artifact a new incident is being created from (linked once it is saved).
  const [seedArtifact, setSeedArtifact] = useState(null)

  // Navigation requests from menus and dialogs (see NavigationContext).
  const navigation = useNavigation()
  const { importInto, clearSearch } = navigation
  /** Show the active incident's tabs: an artifact or the Indicators page in the main area is left. */
  const showIncident = useCallback(() => {
    artifacts.closeArtifact()
    closeLibrary()
    // eslint-disable-next-line react-hooks/exhaustive-deps -- closeArtifact is stable
  }, [closeLibrary])
  useEffect(() => {
    if (!navigation.focus) return
    showIncident()
    setActiveTabId(navigation.focus.tab)
  }, [navigation.focus, showIncident])

  /** Open an incident in the main area (leaving an artifact opened on its own). */
  const { closeArtifact } = artifacts
  const openIncident = useCallback(
    (incidentId) => {
      closeArtifact()
      closeLibrary()
      selectIncident(incidentId)
    },
    [closeArtifact, closeLibrary, selectIncident],
  )

  /**
   * A file to place (dropped anywhere, or chosen in "New analysis"): detect
   * what it is and whether it was analysed before, then ask where it goes.
   */
  const { lookup, startAnalysis, openArtifact } = artifacts
  const { openAdd } = library
  const placeFile = useCallback(
    async (file, { preferAnalysis = false, asEvidence = false } = {}) => {
      const head = await readHead(file)
      // A mailbox (mbox, Maildir archive, PST) is stored and indexed as an
      // artifact of its own; what to import from it is chosen on its page.
      if (!asEvidence && (await mailboxFormatOf(file, head))) {
        showToast({ message: `Uploading ${file.name}…` })
        try {
          const box = await startAnalysis('mailbox', file)
          setPanel('artifacts')
          openArtifact(box.artifactId)
        } catch (err) {
          showToast({ message: `${file.name}: ${err.message}` })
        }
        return
      }
      const route = detectFileRoute({ name: file.name, head })
      // A file of indicators (text, CSV, STIX, MISP, Nik's export) goes to the
      // Indicators: the server reads it and says what it holds.
      if (!preferAnalysis && !asEvidence && mayHoldIndicators({ name: file.name, size: file.size, route })) {
        try {
          const text = await file.text()
          const parsed = await api.post('/iocs/parse', { text })
          if (isIndicatorList(parsed, text)) {
            openAdd({
              text,
              fileName: file.name,
              origin: 'import',
              onNotIndicators: () => {
                openAdd(null)
                placeFile(file, { asEvidence: true })
              },
            })
            return
          }
        } catch {
          /* not readable as indicators: it is placed like any other file */
        }
      }
      const analysable = Boolean(kindForTab(route?.tab ?? 'malware'))
      const known = analysable && file.size <= LOOKUP_MAX_BYTES ? await lookup(await sha256Hex(file)) : []
      setDrop({ file, route, known, preferAnalysis })
    },
    [lookup, openAdd, startAnalysis, openArtifact, setPanel, showToast],
  )

  // Text pasted or dragged onto the app: an address or an indicator Nik can act on.
  const [pasted, setPasted] = useState(null) // recognise() result + { raw, known }
  const [pastedBusy, setPastedBusy] = useState(false)
  const [pastedError, setPastedError] = useState(null)
  const offerText = useCallback(
    async (text) => {
      // Several values at once: the "Add indicators" dialog reads them.
      if (isSeveralValues(text)) {
        try {
          const parsed = await api.post('/iocs/parse', { text: String(text) })
          if (parsed.items.length > 1) openAdd({ text: String(text).trim() })
        } catch {
          /* nothing Nik can read */
        }
        return
      }
      const match = recognise(text)
      if (!match) return
      // A SHA-256 may be a file or an e-mail that was analysed already.
      const known = match.kind === 'sha256' ? ((await lookup(match.value))[0] ?? null) : null
      setPastedError(null)
      setPasted({ ...match, raw: String(text).trim(), known })
    },
    [lookup, openAdd],
  )
  const dismissPasted = useCallback(() => setPasted(null), [])
  useEffect(() => {
    if (!isAuthenticated || !canWrite) return undefined
    const onPaste = (event) => {
      // In a text field, pasting is just pasting.
      if (isTypingTarget(event.target)) return
      const file = event.clipboardData?.files?.[0]
      if (file) placeFile(file)
      else offerText(event.clipboardData?.getData('text') ?? '')
    }
    window.addEventListener('paste', onPaste)
    return () => window.removeEventListener('paste', onPaste)
  }, [isAuthenticated, canWrite, placeFile, offerText])

  // A file dropped anywhere: the overlay while dragging, then the dialog.
  const [dragging, setDragging] = useState(false)
  const [drop, setDrop] = useState(null) // { file, route }
  useEffect(() => {
    if (!isAuthenticated || !canWrite) return undefined
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
  }, [isAuthenticated, canWrite, placeFile, offerText])

  // The Settings page: the address says whether it is open and on which section
  // (/settings/<group>/<section>), so a link opens it and Back leaves it.
  const [settings, setSettings] = useState(() => settingsFromPath(window.location.pathname))
  useEffect(() => onLocationChange(() => setSettings(settingsFromPath(window.location.pathname))), [])
  // Where the page was opened from, to go back there when it is closed.
  const settingsReturn = useRef(null)
  const openSettings = useCallback((section = 'detection') => {
    if (!settingsFromPath(window.location.pathname)) settingsReturn.current = currentPath()
    setPath(settingsPath(section))
  }, [])
  // Moving between sections does not add to the history: Back leaves the page at once.
  const showSettingsSection = useCallback((section) => setPath(settingsPath(section), { replace: true }), [])
  const closeSettings = useCallback(() => {
    if (settingsReturn.current !== null) {
      // Opened from inside the app: Back is the way out, and the entry is not left behind.
      settingsReturn.current = null
      window.history.back()
      return
    }
    // Opened by its link: there is nothing to go back to.
    setPath(activeIncidentId ? `/incident/${encodeURIComponent(activeIncidentId)}` : '/', { replace: true })
  }, [activeIncidentId])
  // Back or Forward left the page: there is nothing to return to any more.
  useEffect(() => {
    if (!settings) settingsReturn.current = null
  }, [settings])

  // The Automations area, in the same way: /automation/<area>/<id>/<tab>.
  const [automation, setAutomation] = useState(() => automationFromPath(window.location.pathname))
  useEffect(() => onLocationChange(() => setAutomation(automationFromPath(window.location.pathname))), [])
  const automationReturn = useRef(null)
  const openAutomation = useCallback(
    (area = 'playbooks', id = null, tab = null, { replace = false, branch = null } = {}) => {
      const inside = Boolean(automationFromPath(window.location.pathname))
      if (!inside) automationReturn.current = currentPath()
      setPath(automationPath(area, id, tab, branch), { replace })
    },
    [],
  )
  const closeAutomation = useCallback(() => {
    const back = automationReturn.current
    automationReturn.current = null
    // Where it was opened from, when that is known; the incident or the start otherwise.
    setPath(back ?? (activeIncidentId ? `/incident/${encodeURIComponent(activeIncidentId)}` : '/'))
  }, [activeIncidentId])
  useEffect(() => {
    if (!automation) automationReturn.current = null
  }, [automation])
  const canAutomate = can('automation.run')
  const { approvals: waitingApprovals, waiting: approvalsWaiting } = useAutomation()
  // The approvals that wait on a run of the incident that is open.
  const incidentApprovals = activeIncidentId
    ? waitingApprovals.filter((approval) => approval.incidentId === activeIncidentId)
    : []
  const automationShown = Boolean(automation) && canAutomate && !settings

  // My tasks, in the same way: /tasks and /tasks/<id>.
  const [tasksRoute, setTasksRoute] = useState(() => tasksFromPath(window.location.pathname))
  useEffect(() => onLocationChange(() => setTasksRoute(tasksFromPath(window.location.pathname))), [])
  const tasksReturn = useRef(null)
  const openTasks = useCallback((id = null, { replace = false } = {}) => {
    if (!tasksFromPath(window.location.pathname)) tasksReturn.current = currentPath()
    setPath(tasksPath(id), { replace })
  }, [])
  const closeTasks = useCallback(() => {
    const back = tasksReturn.current
    tasksReturn.current = null
    setPath(back ?? (activeIncidentId ? `/incident/${encodeURIComponent(activeIncidentId)}` : '/'))
  }, [activeIncidentId])
  useEffect(() => {
    if (!tasksRoute) tasksReturn.current = null
  }, [tasksRoute])
  const { count: taskCount, unread: unreadNotifications } = useTasks()
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const tasksShown = Boolean(tasksRoute) && can('read') && !settings && !automationShown

  // Dashboards, in the same way: /dashboards and /dashboards/<id>.
  const [dashboardsRoute, setDashboardsRoute] = useState(() => dashboardsFromPath(window.location.pathname))
  useEffect(() => onLocationChange(() => setDashboardsRoute(dashboardsFromPath(window.location.pathname))), [])
  const dashboardsReturn = useRef(null)
  const openDashboards = useCallback((id = null, { replace = false } = {}) => {
    if (!dashboardsFromPath(window.location.pathname)) dashboardsReturn.current = currentPath()
    setPath(dashboardsPath(id), { replace })
  }, [])
  const closeDashboards = useCallback(() => {
    const back = dashboardsReturn.current
    dashboardsReturn.current = null
    setPath(back ?? (activeIncidentId ? `/incident/${encodeURIComponent(activeIncidentId)}` : '/'))
  }, [activeIncidentId])
  useEffect(() => {
    if (!dashboardsRoute) dashboardsReturn.current = null
  }, [dashboardsRoute])
  const dashboardsShown = Boolean(dashboardsRoute) && can('read') && !settings && !automationShown && !tasksShown
  // The Playground, in the same way: /playground.
  const [playgroundAsked, setPlaygroundAsked] = useState(() => isPlaygroundPath(window.location.pathname))
  useEffect(() => onLocationChange(() => setPlaygroundAsked(isPlaygroundPath(window.location.pathname))), [])
  const playgroundReturn = useRef(null)
  const openPlayground = useCallback(() => {
    if (!isPlaygroundPath(window.location.pathname)) playgroundReturn.current = currentPath()
    setPath(PLAYGROUND_ROOT)
  }, [])
  const closePlayground = useCallback(() => {
    const back = playgroundReturn.current
    playgroundReturn.current = null
    setPath(back ?? (activeIncidentId ? `/incident/${encodeURIComponent(activeIncidentId)}` : '/'))
  }, [activeIncidentId])
  useEffect(() => {
    if (!playgroundAsked) playgroundReturn.current = null
  }, [playgroundAsked])
  const playgroundShown =
    playgroundAsked && canAutomate && !settings && !automationShown && !tasksShown && !dashboardsShown
  // Whoever chose a dashboard to open at sign-in lands on it, when the address asks for nothing else.
  const landed = useRef(false)
  useEffect(() => {
    if (landed.current || !isAuthenticated) return
    landed.current = true
    const wanted = landingDashboard()
    if (wanted && window.location.pathname === '/' && can('read')) {
      dashboardsReturn.current = '/'
      setPath(dashboardsPath(wanted), { replace: true })
    }
  }, [isAuthenticated, can])

  // The list of keyboard shortcuts ("?" or the header button).
  const [shortcutsOpen, setShortcutsOpen] = useState(false)

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
    if (!isAuthenticated || !canRead) return undefined
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
  }, [isAuthenticated, canRead])

  // The side panel can be made wider or narrower, like every side panel (ui/ResizeHandle.jsx).
  const sidebarPane = useResizablePane('sidebar', {
    initial: SIDEBAR_DEFAULT_WIDTH,
    min: SIDEBAR_MIN_WIDTH,
    max: 560,
    legacyKey: SIDEBAR_WIDTH_KEY,
  })

  // The tabs of the incident on screen: those its type shows, in the order its type gives them.
  const { types: incidentTypes } = useFields()
  const activeType = typeOf(incidentTypes, activeIncident ?? activeSummary)
  const allTabs = useMemo(() => orderTabs(visibleTabs(can), activeType?.layout), [can, activeType])
  // The bar holds the tabs; the kinds of evidence are inside the Evidence tab, in the same order.
  const shownTabs = useMemo(() => {
    const bar = allTabs.filter((tab) => !tab.evidence)
    bar.ordered = Boolean(activeType?.layout?.tabs?.length)
    return bar
  }, [allTabs, activeType])
  const evidenceKinds = useMemo(() => allTabs.filter((tab) => tab.evidence), [allTabs])
  // A tab the account may not see (its roles changed, a link named it), or that the type hides, falls back to the
  // first; the address of a kind of evidence (mail, malware…) is the Evidence tab on that kind.
  const resolved = resolveTab(allTabs, activeTabId)
  const activeTab = resolved.bar ?? getTabById(ANALYSIS_TABS[0].id)
  const ActiveTabComponent = activeTab.component
  // The tab is remembered for each type of incident: a phishing case opens on Mail if that is where one works.
  const typeKey = activeType?.id ?? null
  // Applied when the type on screen changes; among incidents of one type the tab stays where it is.
  useEffect(() => {
    if (!typeKey) return
    const remembered = localStorage.getItem(`${TAB_KEY}.${typeKey}`)
    if (remembered) setActiveTabId(remembered)
  }, [typeKey])
  const chooseTab = useCallback(
    (tabId) => {
      setActiveTabId(tabId)
      if (typeKey) localStorage.setItem(`${TAB_KEY}.${typeKey}`, tabId)
    },
    [typeKey],
  )

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
      showIncident()
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
    ...(canWrite
      ? [
          { id: 'new', label: 'New incident', icon: Plus, run: openCreateModal },
          {
            id: 'analysis',
            label: 'New analysis (no incident)',
            icon: Microscope,
            keywords: 'artifact file mail upload',
            run: () => setAnalysisOpen(true),
          },
        ]
      : []),
    ...(activeIncident
      ? allTabs.map((tab) => ({
          id: `tab:${tab.id}`,
          label: `Go to ${tab.label}`,
          icon: tab.icon,
          hint: 'tab',
          run: () => {
            showIncident()
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
    ...(canAutomate
      ? [
          {
            id: 'automations',
            label: 'Open automations',
            icon: Workflow,
            keywords: 'playbooks canvas runs scripts',
            run: () => openAutomation(),
          },
        ]
      : []),
    { id: 'settings', label: 'Open settings', icon: Settings, run: () => openSettings('detection') },
    ...(canWrite
      ? [
          {
            id: 'allowlist',
            label: 'Edit the IOC allowlist',
            icon: ShieldCheck,
            keywords: 'settings indicators',
            run: () => openSettings('allowlist'),
          },
        ]
      : []),
    { id: 'logout', label: 'Sign out', icon: LogOut, run: logout },
  ]

  // ---- Initial async load of incidents from the API ----
  if (loading && canRead) {
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
        onPanel={(next) => {
          if (settings) closeSettings()
          else if (automationShown) closeAutomation()
          else if (tasksShown) closeTasks()
          else if (dashboardsShown) closeDashboards()
          else if (playgroundShown) closePlayground()
          setPanel(next)
        }}
        counts={{
          incidents: incidents.length,
          artifacts: Object.values(artifacts.counts).reduce((sum, n) => sum + n, 0),
          iocs: library.counts.all,
          alerts: library.alerts,
          approvals: canAutomate ? approvalsWaiting : 0,
          tasks: taskCount.mine,
          tasksOverdue: taskCount.overdue,
          unread: unreadNotifications,
        }}
        can={can}
        onSearch={() => setPaletteOpen(true)}
        onAccount={() => openSettings('account')}
        onSettings={() => (settings ? closeSettings() : openSettings('detection'))}
        settingsOpen={Boolean(settings)}
        onAutomation={() => (automationShown ? closeAutomation() : openAutomation())}
        automationOpen={automationShown}
        onTasks={() => (tasksShown ? closeTasks() : openTasks())}
        tasksOpen={tasksShown}
        onDashboards={() => (dashboardsShown ? closeDashboards() : openDashboards())}
        dashboardsOpen={dashboardsShown}
        onPlayground={() => (playgroundShown ? closePlayground() : openPlayground())}
        playgroundOpen={playgroundShown}
        onNotifications={() => setNotificationsOpen(true)}
      />
      {notificationsOpen && <NotificationsDialog onClose={() => setNotificationsOpen(false)} />}
      {settings && (
        <SettingsPage
          section={settings.id}
          onSection={showSettingsSection}
          onClose={closeSettings}
          onOpenArtifact={(id) => {
            setPanel('artifacts')
            openArtifact(id)
          }}
        />
      )}
      {automationShown && (
        <Suspense
          fallback={
            <p role="status" className="flex-1 p-6 font-mono text-sm text-fg-muted">
              Loading automations…
            </p>
          }
        >
          <AutomationPage
            route={automation}
            onNavigate={openAutomation}
            onClose={closeAutomation}
            onOpenSettings={openSettings}
            onOpenIncident={openIncident}
          />
        </Suspense>
      )}
      {tasksShown && (
        <Suspense
          fallback={
            <p role="status" className="flex-1 p-6 font-mono text-sm text-fg-muted">
              Loading tasks…
            </p>
          }
        >
          <TasksPage taskId={tasksRoute.id} onSelect={openTasks} onClose={closeTasks} onOpenIncident={openIncident} />
        </Suspense>
      )}
      {dashboardsShown && (
        <Suspense
          fallback={
            <p role="status" className="flex-1 p-6 font-mono text-sm text-fg-muted">
              Loading dashboards…
            </p>
          }
        >
          <DashboardsPage
            dashboardId={dashboardsRoute.id}
            onSelect={openDashboards}
            onClose={closeDashboards}
            onOpenIncident={openIncident}
          />
        </Suspense>
      )}
      {playgroundShown && (
        <Suspense
          fallback={
            <p role="status" className="flex-1 p-6 font-mono text-sm text-fg-muted">
              Loading the playground…
            </p>
          }
        >
          <PlaygroundPage onClose={closePlayground} />
        </Suspense>
      )}
      {!settings && !automationShown && !tasksShown && !dashboardsShown && !playgroundShown && panel && canRead && (
        <>
          <Sidebar
            panel={panel}
            width={sidebarPane.width}
            onCreateIncident={openCreateModal}
            onNewAnalysis={() => setAnalysisOpen(true)}
            onSelectIncident={openIncident}
            incidentShown={!artifactOpen && !libraryOpen}
            onOpenReport={() => setReportOpen(true)}
          />
          <ResizeHandle {...sidebarPane.handle} label="Resize the side panel" />
        </>
      )}

      <div
        className={
          settings || automationShown || tasksShown || dashboardsShown || playgroundShown
            ? 'hidden'
            : 'flex min-w-0 flex-1 flex-col'
        }
      >
        <Header
          onOpenSearch={() => setPaletteOpen(true)}
          onOpenShortcuts={() => setShortcutsOpen(true)}
          onOpenReport={activeIncident && !artifactOpen && !libraryOpen ? () => setReportOpen(true) : null}
          artifactView={artifactOpen}
          libraryView={libraryOpen}
        />
        <div className="flex min-h-0 flex-1 flex-col min-[1100px]:flex-row">
          {canRead && !artifactOpen && !libraryOpen && activeIncident && <IncidentPanel incident={activeIncident} />}
          <div className="flex min-h-0 min-w-0 flex-1 flex-col">
            {canRead && !artifactOpen && !libraryOpen && (
              <TabBar activeTabId={activeTab.id} onChange={chooseTab} tabs={shownTabs} />
            )}
            {canRead && !artifactOpen && !libraryOpen && incidentApprovals.length > 0 && (
              <div className="flex shrink-0 flex-col gap-2 border-b border-line px-6 py-3">
                {incidentApprovals.map((approval) => (
                  <ApprovalBanner
                    key={approval.id}
                    approval={approval}
                    onOpenRun={(runId) => openAutomation('runs', runId)}
                  />
                ))}
              </div>
            )}

            {storageError && (
              <div
                role="alert"
                className="flex shrink-0 items-center gap-2 border-b border-high-line bg-high-soft px-6 py-2.5 text-sm text-high-fg"
              >
                <AlertTriangle className="h-4 w-4 shrink-0" />
                <span className="min-w-0 flex-1">
                  {unsavedChanges ? `Changes not saved yet: ${storageError}` : storageError}
                </span>
                {unsavedChanges && (
                  <Button size="xs" variant="secondary" onClick={retrySave}>
                    Retry now
                  </Button>
                )}
              </div>
            )}

            <div className="flex min-h-0 flex-1">
              <main className="@container min-w-0 flex-1 overflow-y-auto p-6">
                {!canRead ? (
                  <div className="flex h-full items-center justify-center">
                    <EmptyState
                      illustration={<AsciiSkull preset="medium" eyes="closed" tone="muted" />}
                      title="Nothing to open here"
                      message="Your roles do not include reading incidents, artifacts and indicators. What they do include is in Settings; an admin can give your account more roles."
                      action={
                        <Button icon={Settings} onClick={() => openSettings('account')}>
                          Open settings
                        </Button>
                      }
                    />
                  </div>
                ) : libraryOpen ? (
                  <IocLibraryPage onOpenIncident={openIncident} />
                ) : artifactOpen ? (
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
                      {activeTab.id === EVIDENCE_TAB ? (
                        <EvidenceTab
                          incident={activeIncident}
                          kinds={evidenceKinds}
                          kind={resolved.kind}
                          onKind={chooseTab}
                        />
                      ) : (
                        <ActiveTabComponent incident={activeIncident} />
                      )}
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
                      message={
                        canWrite
                          ? 'Create an incident to work a case, or analyse a file or an e-mail on its own. You can also drop a file anywhere.'
                          : 'Choose an incident on the left to read it.'
                      }
                      action={
                        canWrite && (
                          <div className="flex flex-wrap justify-center gap-2">
                            <Button icon={Plus} onClick={openCreateModal}>
                              New incident
                            </Button>
                            <Button variant="secondary" icon={Microscope} onClick={() => setAnalysisOpen(true)}>
                              New analysis
                            </Button>
                          </div>
                        )
                      }
                    />
                  </div>
                )}
              </main>
            </div>
          </div>
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

      {canAutomate && <RunPlaybookDialog onStarted={(run) => openAutomation('runs', run.id)} />}
      <CloseIncidentDialog />

      <KeyboardShortcuts open={shortcutsOpen} onOpenChange={setShortcutsOpen} />
      <SessionExpiredDialog unsavedChanges={unsavedChanges} />
      <PastePrompt
        pasted={pasted}
        busy={pastedBusy}
        error={pastedError}
        onDismiss={dismissPasted}
        onAdd={(value) => {
          setPasted(null)
          openAdd({ text: value })
        }}
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
          showIncident()
          setActiveTabId(tab)
        }}
      />
    </div>
  )
}
