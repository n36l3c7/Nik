import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../services/api.js'
import { libraryPath, viewFromPath } from '../domain/iocLibrary.js'
import AddIocsDialog from '../components/iocs/AddIocsDialog.jsx'
import BulkCheckDialog from '../components/iocs/BulkCheckDialog.jsx'
import ExportIocsDialog from '../components/iocs/ExportIocsDialog.jsx'
import ListDialog from '../components/iocs/ListDialog.jsx'
import { useAuth } from './AuthContext.jsx'
import { useToast } from './ToastContext.jsx'

/*
 * ============================================================================
 * IOC LIBRARY CONTEXT — every indicator Nik knows, lists, bulk actions
 * ============================================================================
 *
 * Holds what the rail and the side panel show (counts, lists, unseen alerts),
 * the view open in the main area (permalinks: /iocs, /iocs/lists/<id>,
 * /iocs/alerts), the bulk checks running in the background, and the dialogs
 * any screen can open: add indicators, export, bulk check, make a list.
 *
 * A "scope" says which indicators an action is about, as the API takes it:
 * { items: [{type, value}] } | { list: id } | { incident: id } | { filters }.
 */

const IocLibraryContext = createContext(null)
const NO_COUNTS = { all: 0, added: 0, malicious: 0, suspicious: 0, harmless: 0, unchecked: 0, expired: 0 }
const POLL_MS = 4000

const viewFromUrl = () => (typeof window === 'undefined' ? null : viewFromPath(window.location.pathname))
const active = (check) => check.status === 'running' || check.status === 'waiting'

export function IocLibraryProvider({ children }) {
  const { isAuthenticated } = useAuth()
  const { showToast } = useToast()
  const [view, setView] = useState(viewFromUrl)
  const [quick, setQuick] = useState('all') // the side panel's quick filter
  const [counts, setCounts] = useState(NO_COUNTS)
  const [lists, setLists] = useState([])
  const [alerts, setAlerts] = useState(0)
  const [checks, setChecks] = useState([])
  const [version, setVersion] = useState(0)
  const [adding, setAdding] = useState(null) // { text, fileName, origin, list, onNotIndicators }
  const [exporting, setExporting] = useState(null) // { scope, label, count }
  const [checking, setChecking] = useState(null) // { scope, label }
  const [listForm, setListForm] = useState(null) // { list } to edit, { scope, count } to make

  const refresh = useCallback(() => setVersion((v) => v + 1), [])

  // What the rail and the panel show.
  useEffect(() => {
    if (!isAuthenticated) {
      setCounts(NO_COUNTS)
      setLists([])
      setAlerts(0)
      return undefined
    }
    let cancelled = false
    Promise.all([api.get('/iocs?limit=1'), api.get('/iocs/lists')])
      .then(([library, found]) => {
        if (cancelled) return
        setCounts(library.counts)
        setAlerts(library.alerts)
        setLists(found.lists)
      })
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [isAuthenticated, version])

  // Bulk checks: loaded once, then polled while one is going.
  const before = useRef(new Map())
  const loadChecks = useCallback(async () => {
    try {
      const { checks: found } = await api.get('/iocs/checks')
      for (const check of found) {
        const was = before.current.get(check.id)
        if (was && active({ status: was }) && !active(check)) {
          showToast({
            message:
              check.status === 'done'
                ? `Check finished: ${check.label} (${check.total} indicators).`
                : `Check stopped: ${check.label}.`,
          })
          refresh()
        }
        if (was === 'running' && check.status === 'waiting') showToast({ message: check.message, duration: 10_000 })
        before.current.set(check.id, check.status)
      }
      setChecks(found)
      return found
    } catch {
      return []
    }
  }, [showToast, refresh])
  const anyActive = checks.some(active)
  useEffect(() => {
    if (isAuthenticated) loadChecks()
    else setChecks([])
  }, [isAuthenticated, loadChecks])
  useEffect(() => {
    if (!isAuthenticated || !anyActive) return undefined
    const timer = setInterval(() => {
      loadChecks()
      refresh()
    }, POLL_MS)
    return () => clearInterval(timer)
  }, [isAuthenticated, anyActive, loadChecks, refresh])

  // Back and forward.
  useEffect(() => {
    const onPopState = () => setView(viewFromUrl())
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  const openView = useCallback((next) => {
    setView(next)
    const path = libraryPath(next)
    if (window.location.pathname !== path) window.history.pushState({ iocs: true }, '', path)
  }, [])
  /** Leave the library (the caller restores the incident's or the artifact's URL). */
  const closeView = useCallback(() => setView(null), [])

  /** Open the dialog (optionally with text or a file's content); null closes it. */
  const openAdd = useCallback((options = {}) => setAdding(options === null ? null : { text: '', ...options }), [])
  const openExport = useCallback((scope, label, count) => setExporting({ scope, label, count }), [])
  const openCheck = useCallback((scope, label) => setChecking({ scope, label }), [])
  const openListForm = useCallback((options = {}) => setListForm(options), [])

  const markAlertsSeen = useCallback(async () => {
    await api.post('/iocs/alerts/seen', {})
    setAlerts(0)
  }, [])

  const value = useMemo(
    () => ({
      view,
      openView,
      closeView,
      quick,
      setQuick,
      counts,
      lists,
      alerts,
      checks,
      version,
      refresh,
      openAdd,
      openExport,
      openCheck,
      openListForm,
      markAlertsSeen,
    }),
    [
      view,
      openView,
      closeView,
      quick,
      counts,
      lists,
      alerts,
      checks,
      version,
      refresh,
      openAdd,
      openExport,
      openCheck,
      openListForm,
      markAlertsSeen,
    ],
  )

  return (
    <IocLibraryContext.Provider value={value}>
      {children}
      {isAuthenticated && (
        <>
          <AddIocsDialog
            request={adding}
            lists={lists}
            onClose={() => setAdding(null)}
            onSaved={(result) => {
              setAdding(null)
              refresh()
              if (result.check) loadChecks()
              const where = result.list ? ` in "${result.list.name}"` : ''
              showToast({
                message: `${result.added} added${result.existing ? `, ${result.existing} already known` : ''}${where}.`,
              })
              if (result.list) openView({ kind: 'list', id: result.list.id })
              else if (!view) openView({ kind: 'all' })
            }}
          />
          <ExportIocsDialog request={exporting} onClose={() => setExporting(null)} />
          <BulkCheckDialog
            request={checking}
            onClose={() => setChecking(null)}
            onStarted={() => {
              loadChecks()
              refresh()
            }}
          />
          <ListDialog
            request={listForm}
            onClose={() => setListForm(null)}
            onSaved={(list, made) => {
              setListForm(null)
              refresh()
              showToast({ message: made ? `List "${list.name}" made (${list.count} indicators).` : 'List saved.' })
              if (made) openView({ kind: 'list', id: list.id })
            }}
          />
        </>
      )}
    </IocLibraryContext.Provider>
  )
}

export function useIocLibrary() {
  const ctx = useContext(IocLibraryContext)
  if (!ctx) throw new Error('useIocLibrary must be used inside <IocLibraryProvider>')
  return ctx
}
