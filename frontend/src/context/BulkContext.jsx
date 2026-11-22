import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import BulkDialog from '../components/bulk/BulkDialog.jsx'
import BulkResult from '../components/bulk/BulkResult.jsx'
import { jobClean, resultWords } from '../domain/bulk.js'
import { followBulk } from '../lib/bulk.js'
import { api } from '../services/api.js'
import { useAuth } from './AuthContext.jsx'
import { useToast } from './ToastContext.jsx'

/*
 * ============================================================================
 * BULK CONTEXT — one action asked of many rows of a list
 * ============================================================================
 *
 * A list that has a selection asks here for an action on it:
 *
 *   const { askBulk, showResult } = useBulk()
 *   askBulk({
 *     list: 'incidents',                  // incidents | artifacts | indicators
 *     action: 'tags',                     // the name the server knows it by
 *     title: 'Change the tags',           // what the dialog is called
 *     selection: picked.body({ q }),      // { ids } or { query }
 *     form: { kind: 'tags' },             // what is asked before (see BulkDialog); none: `params`
 *     params: {},
 *     onStarted: picked.reset,            // the server has the job: the selection is emptied
 *     onDone: (job) => …,                 // once the job is over: read the list again
 *   })
 *
 * One dialog asks what the action needs, shows what the server says it would
 * do (how many, what it sets in motion, what must be typed) and starts it.
 * "What it did" (`showResult(job or id)`) is the result, there afterwards
 * from Settings → System → Bulk actions too.
 */

const BulkContext = createContext(null)

export function BulkProvider({ children }) {
  const [request, setRequest] = useState(null)
  const [result, setResult] = useState(null) // a job, or its id
  const askBulk = useCallback((asked) => setRequest({ ...asked, key: Date.now() }), [])
  const showResult = useCallback((job) => setResult(job), [])
  const value = useMemo(() => ({ askBulk, showResult }), [askBulk, showResult])

  // A job of this account that still runs when the page is opened (it was reloaded, or the job was
  // asked from another window) is followed in the tray again, once, until it ends.
  const { isAuthenticated, can, currentUser } = useAuth()
  const { showToast } = useToast()
  const followed = useRef(new Set())
  const reads = isAuthenticated && can('read')
  const me = currentUser?.username ?? ''
  useEffect(() => {
    if (!reads || !me) return undefined
    let alive = true
    api
      .get('/bulk?limit=10', { background: true })
      .then((found) => {
        for (const job of found.jobs) {
          if (!alive || job.state !== 'running' || followed.current.has(job.id)) continue
          followed.current.add(job.id)
          followBulk(job).then(
            (ended) => {
              if (jobClean(ended)) showToast({ message: `${ended.label}: ${resultWords(ended)}.` })
              else setResult(ended)
            },
            () => {},
          )
        }
      })
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [reads, me, showToast])
  return (
    <BulkContext.Provider value={value}>
      {children}
      {request && (
        <BulkDialog key={request.key} request={request} onClose={() => setRequest(null)} onResult={setResult} />
      )}
      {result && (
        <BulkResult
          key={typeof result === 'string' ? result : result.id}
          job={result}
          onClose={() => setResult(null)}
          onResult={setResult}
        />
      )}
    </BulkContext.Provider>
  )
}

export function useBulk() {
  const context = useContext(BulkContext)
  if (!context) throw new Error('useBulk must be used inside <BulkProvider>')
  return context
}
