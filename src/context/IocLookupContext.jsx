import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { Crosshair, ExternalLink, ShieldCheck } from 'lucide-react'
import { Badge, Modal } from '../components/ui/index.js'
import { api } from '../services/api.js'
import { IOC_TYPES, sourceLabel } from '../utils/iocs.js'
import { formatDateTime } from '../utils/time.js'
import { useIncidents } from './IncidentContext.jsx'

/*
 * "Where seen": any table can call openIoc(type, value) to show, in one
 * shared dialog, every incident the indicator appears in (all analysts'),
 * from GET /api/iocs/lookup, with a link to open each incident.
 */

const IocLookupContext = createContext(null)

function WhereSeen({ lookup, onClose }) {
  const { activeIncidentId, selectIncident } = useIncidents()
  const [state, setState] = useState({ loading: true, data: null, error: null })

  useEffect(() => {
    if (!lookup) return undefined
    const controller = new AbortController()
    setState({ loading: true, data: null, error: null })
    const query = new URLSearchParams({ type: lookup.type, value: lookup.value })
    api
      .get(`/iocs/lookup?${query}`, { signal: controller.signal })
      .then((data) => setState({ loading: false, data, error: null }))
      .catch((err) => {
        if (!controller.signal.aborted)
          setState({ loading: false, data: null, error: err?.message ?? 'Lookup failed.' })
      })
    return () => controller.abort()
  }, [lookup])

  const meta = IOC_TYPES[lookup?.type] ?? { label: lookup?.type }
  const incidents = state.data?.incidents ?? []

  return (
    <Modal open={Boolean(lookup)} onClose={onClose} title="Where seen" maxWidth="max-w-2xl">
      {lookup && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <Badge color={meta.color}>{meta.label}</Badge>
            <code className="break-all font-mono text-sm text-fg">{lookup.value}</code>
            {state.data?.allowlisted && (
              <Badge color="slate" title="On the IOC allowlist (Settings)">
                <ShieldCheck className="h-3 w-3" /> allowlisted
              </Badge>
            )}
          </div>
          {state.loading && <p className="font-mono text-xs text-fg-muted">Searching every incident…</p>}
          {state.error && <p className="text-xs text-high">{state.error}</p>}
          {!state.loading && !state.error && incidents.length === 0 && (
            <p className="text-sm text-fg-muted">
              Not in any saved incident yet (changes made in the last seconds are indexed when they are saved).
            </p>
          )}
          {incidents.length > 0 && (
            <>
              <p className="text-xs text-fg-muted">
                Seen in <strong className="text-fg">{incidents.length}</strong>{' '}
                {incidents.length === 1 ? 'incident' : 'incidents'}.
              </p>
              <ul className="divide-y divide-line-soft border border-line">
                {incidents.map((incident) => {
                  const current = incident.id === activeIncidentId
                  return (
                    <li key={incident.id} className="flex flex-wrap items-start gap-3 px-3 py-2">
                      <div className="min-w-0 flex-1 space-y-1">
                        <p className="flex items-center gap-2 text-sm font-medium text-fg">
                          {incident.name || incident.id}
                          {current && <Badge color="emerald">this incident</Badge>}
                        </p>
                        <div className="flex flex-wrap gap-1">
                          {incident.sources.map((source) => (
                            <Badge key={source} color="slate">
                              {sourceLabel(source)}
                            </Badge>
                          ))}
                        </div>
                        <p className="font-mono text-[11px] text-fg-muted">
                          {incident.count}× ·{' '}
                          {incident.firstSeen
                            ? `${formatDateTime(incident.firstSeen)} → ${formatDateTime(incident.lastSeen)}`
                            : 'no timestamp'}
                        </p>
                      </div>
                      {!current && (
                        <button
                          type="button"
                          onClick={() => {
                            selectIncident(incident.id)
                            onClose()
                          }}
                          className="inline-flex items-center gap-1 text-xs text-accent hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                        >
                          <ExternalLink className="h-3.5 w-3.5" /> Open
                        </button>
                      )}
                    </li>
                  )
                })}
              </ul>
            </>
          )}
        </div>
      )}
    </Modal>
  )
}

export function IocLookupProvider({ children }) {
  const [lookup, setLookup] = useState(null)
  const openIoc = useCallback((type, value) => setLookup({ type, value: String(value) }), [])
  const close = useCallback(() => setLookup(null), [])
  const value = useMemo(() => ({ openIoc }), [openIoc])
  return (
    <IocLookupContext.Provider value={value}>
      {children}
      <WhereSeen lookup={lookup} onClose={close} />
    </IocLookupContext.Provider>
  )
}

/** `{ openIoc(type, value) }` — show every incident an indicator is in. */
export function useIocLookup() {
  const ctx = useContext(IocLookupContext)
  if (!ctx) throw new Error('useIocLookup must be used inside <IocLookupProvider>')
  return ctx
}

/** An indicator value that opens "Where seen" when clicked. */
export function IocValue({ type, value, className = '' }) {
  const { openIoc } = useIocLookup()
  if (!type) return <span className={className}>{value}</span>
  return (
    <button
      type="button"
      onClick={(event) => {
        event.stopPropagation()
        openIoc(type, value)
      }}
      title="Where else was this seen?"
      className={[
        'group inline-flex max-w-full items-center gap-1 text-left underline decoration-dotted decoration-fg-subtle underline-offset-2',
        'hover:text-accent-fg hover:decoration-solid focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
        className,
      ].join(' ')}
    >
      <span className="break-all">{value}</span>
      <Crosshair className="h-3 w-3 shrink-0 opacity-0 transition group-hover:opacity-100" aria-hidden="true" />
    </button>
  )
}
