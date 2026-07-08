import { Suspense, useState } from 'react'
import { AlertTriangle, FolderOpen, Plus, RefreshCw, ServerCrash } from 'lucide-react'
import { useAuth } from './context/AuthContext.jsx'
import { useIncidents } from './context/IncidentContext.jsx'
import { ANALYSIS_TABS, getTabById } from './config/tabs.js'
import { Button, EmptyState, Modal, Spinner } from './components/ui/index.js'
import Sidebar from './components/layout/Sidebar.jsx'
import Header from './components/layout/Header.jsx'
import TabBar from './components/layout/TabBar.jsx'
import SettingsModal from './components/settings/SettingsModal.jsx'
import LoginScreen from './components/auth/LoginScreen.jsx'
import FirstRunSetup from './components/auth/FirstRunSetup.jsx'
import UserManagement from './components/auth/UserManagement.jsx'
import AuditLogView from './components/audit/AuditLogView.jsx'

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

/** Full-screen boot splash shown while the session probe is in flight. */
function ConnectingScreen() {
  return (
    <div className="flex h-screen items-center justify-center bg-slate-100 dark:bg-slate-950">
      <div className="flex flex-col items-center gap-3">
        <Spinner className="h-8 w-8 text-cyan-600 dark:text-cyan-400" />
        <p className="text-sm text-slate-500 dark:text-slate-400">Connecting…</p>
      </div>
    </div>
  )
}

/** Full-screen error card shown when the backend cannot be reached. */
function UnreachableScreen({ error, onRetry }) {
  return (
    <div className="flex h-screen items-center justify-center bg-slate-100 p-4 dark:bg-slate-950">
      <div className="w-full max-w-sm rounded-xl border border-slate-200 bg-white p-6 text-center shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-red-100 text-red-600 dark:bg-red-500/10 dark:text-red-400">
          <ServerCrash className="h-6 w-6" aria-hidden="true" />
        </div>
        <h1 className="text-base font-semibold text-slate-900 dark:text-white">
          Cannot reach the server
        </h1>
        <p className="mt-1.5 text-sm text-slate-500 dark:text-slate-400">
          The application could not contact the backend API. Check that the
          service is running, then try again.
        </p>
        {error && (
          <p className="mt-3 break-words rounded-lg bg-slate-100 px-3 py-2 font-mono text-xs text-slate-500 dark:bg-slate-950 dark:text-slate-400">
            {error}
          </p>
        )}
        <Button icon={RefreshCw} onClick={onRetry} className="mt-5 w-full justify-center">
          Retry
        </Button>
      </div>
    </div>
  )
}

export default function App() {
  const { hasUsers, isAuthenticated, authReady, serverError, retry } = useAuth()
  const { activeIncident, storageError, createIncident, loading } = useIncidents()

  const [activeTabId, setActiveTabId] = useState(ANALYSIS_TABS[0].id)

  // "New incident" modal (asks for host and/or username, not a name).
  const [createOpen, setCreateOpen] = useState(false)
  const [host, setHost] = useState('')
  const [username, setUsername] = useState('')

  const [settingsOpen, setSettingsOpen] = useState(false)
  const [usersOpen, setUsersOpen] = useState(false)
  const [auditOpen, setAuditOpen] = useState(false)

  const activeTab = getTabById(activeTabId) ?? ANALYSIS_TABS[0]
  const ActiveTabComponent = activeTab.component

  // ---- Boot gate (session probe / server reachability) ----
  if (!authReady) return <ConnectingScreen />
  if (serverError) return <UnreachableScreen error={serverError} onRetry={retry} />

  // ---- Auth gate ----
  if (!hasUsers) return <FirstRunSetup />
  if (!isAuthenticated) return <LoginScreen />

  const openCreateModal = () => {
    setHost('')
    setUsername('')
    setCreateOpen(true)
  }

  const handleCreateSubmit = (event) => {
    event.preventDefault()
    if (!host.trim() && !username.trim()) return // need host and/or username
    createIncident({ host, username })
    setCreateOpen(false)
  }

  // ---- Initial async load of incidents from the API ----
  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-slate-100 dark:bg-slate-950">
        <div className="flex flex-col items-center gap-3">
          <Spinner className="h-8 w-8 text-cyan-600 dark:text-cyan-400" />
          <p className="text-sm text-slate-500 dark:text-slate-400">Loading incidents…</p>
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar
        onCreateIncident={openCreateModal}
        onOpenAudit={() => setAuditOpen(true)}
        onOpenUsers={() => setUsersOpen(true)}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <Header onOpenSettings={() => setSettingsOpen(true)} />
        <TabBar activeTabId={activeTabId} onChange={setActiveTabId} />

        {storageError && (
          <div
            role="alert"
            className="flex shrink-0 items-center gap-2 border-b border-red-200 bg-red-50 px-6 py-2.5 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/60 dark:text-red-400"
          >
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span>{storageError}</span>
          </div>
        )}

        <main className="flex-1 overflow-y-auto p-6">
          {activeIncident ? (
            <Suspense
              fallback={
                <div className="flex items-center justify-center py-24">
                  <Spinner className="h-8 w-8 text-cyan-600 dark:text-cyan-400" />
                </div>
              }
            >
              <ActiveTabComponent incident={activeIncident} />
            </Suspense>
          ) : (
            <div className="flex h-full items-center justify-center">
              <EmptyState
                icon={FolderOpen}
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
      </div>

      {/* New incident modal — identified by host and/or username */}
      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="New incident"
        footer={
          <>
            <Button variant="secondary" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" form="form-new-incident" disabled={!host.trim() && !username.trim()}>
              Create incident
            </Button>
          </>
        }
      >
        <form id="form-new-incident" onSubmit={handleCreateSubmit} className="space-y-4">
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Identify the incident by host, user, or both. This is a label (not a
            unique id), so duplicates are allowed.
          </p>
          <div>
            <label htmlFor="new-host" className="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">
              Host
            </label>
            <input
              id="new-host"
              type="text"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="e.g. WKS-FINANCE-01"
              autoFocus
              className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 dark:border-slate-800 dark:bg-slate-950 dark:text-white dark:placeholder:text-slate-500"
            />
          </div>
          <div>
            <label htmlFor="new-username" className="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">
              User
            </label>
            <input
              id="new-username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. m.rossi"
              className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 dark:border-slate-800 dark:bg-slate-950 dark:text-white dark:placeholder:text-slate-500"
            />
          </div>
        </form>
      </Modal>

      <SettingsModal open={settingsOpen} onClose={() => setSettingsOpen(false)} />
      <UserManagement open={usersOpen} onClose={() => setUsersOpen(false)} />
      <AuditLogView open={auditOpen} onClose={() => setAuditOpen(false)} />
    </div>
  )
}
