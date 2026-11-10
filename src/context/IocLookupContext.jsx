import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { Copy, Crosshair, ExternalLink, Search, ShieldCheck } from 'lucide-react'
import { Badge, Button, Modal } from '../components/ui/index.js'
import IocReputation from '../components/tabs/iocs/IocReputation.jsx'
import { api } from '../services/api.js'
import { IOC_TYPES, allowlistOptions, defang, sourceLabel } from '../utils/iocs.js'
import { formatDateTime } from '../utils/time.js'
import { useAuth } from './AuthContext.jsx'
import { useContextMenu } from './ContextMenuContext.jsx'
import { useIncidents } from './IncidentContext.jsx'
import { useNavigation } from './NavigationContext.jsx'
import { useSettings } from './SettingsContext.jsx'
import { useToast } from './ToastContext.jsx'

/*
 * Indicators anywhere in the app:
 *   - openIoc(type, value): "Where seen", every incident the indicator appears
 *     in (all analysts'), from GET /api/iocs/lookup, with a link to each;
 *   - openAllowlist(type, value): add it, or a wider entry (its domain, its
 *     /24), to the shared IOC allowlist, with Undo;
 *   - iocMenu(event, type, value): the right-click menu of an indicator.
 * <IocValue> renders a value that does all three.
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
          <IocReputation type={lookup.type} value={state.data?.value ?? lookup.value} />
        </div>
      )}
    </Modal>
  )
}

function AllowlistDialog({ target, onClose }) {
  const { iocAllowlist, setIocAllowlist } = useSettings()
  const { currentUser } = useAuth()
  const { showToast } = useToast()
  const options = useMemo(() => (target ? allowlistOptions(target.type, target.value) : []), [target])
  const [choice, setChoice] = useState(0)
  const [note, setNote] = useState('')

  useEffect(() => {
    setChoice(options.length > 1 && target?.type !== 'ip' ? 1 : 0)
    setNote('')
  }, [options, target])

  if (!target) return null
  const loaded = Array.isArray(iocAllowlist)
  const option = options[choice]
  const already =
    loaded && option && iocAllowlist.some((line) => line.trim().toLowerCase() === option.entry.toLowerCase())

  const add = () => {
    if (!loaded || !option) return
    const comment = `# ${note.trim() || target.value} · added by ${currentUser?.username ?? 'unknown'} on ${new Date()
      .toISOString()
      .slice(0, 10)}`
    const before = iocAllowlist
    setIocAllowlist([...before, comment, option.entry])
    showToast({
      message: `${option.entry} added to the IOC allowlist.`,
      action: { label: 'Undo', run: () => setIocAllowlist(before) },
      duration: 8000,
    })
    onClose()
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="Add to the allowlist"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button icon={ShieldCheck} onClick={add} disabled={!loaded || already}>
            {already ? 'Already in the allowlist' : 'Add to the allowlist'}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <p className="text-sm text-fg">
          Hide <code className="break-all font-mono">{target.value}</code> in every incident and leave it out of the
          exports. Everyone shares the allowlist (Settings → IOC allowlist).
        </p>
        <fieldset className="space-y-2">
          <legend className="sr-only">What to allowlist</legend>
          {options.map((o, i) => (
            <label
              key={o.entry}
              className={[
                'flex cursor-pointer items-start gap-2 border px-3 py-2 text-sm',
                i === choice ? 'border-accent-strong bg-accent-soft' : 'border-line',
              ].join(' ')}
            >
              <input
                type="radio"
                name="allowlist-choice"
                checked={i === choice}
                onChange={() => setChoice(i)}
                className="mt-1 accent-accent"
              />
              <span className="min-w-0">
                <span className="block break-all font-mono text-xs text-fg">{o.entry}</span>
                <span className="text-xs text-fg-muted">{o.label}</span>
              </span>
            </label>
          ))}
        </fieldset>
        <label htmlFor="allowlist-note" className="block space-y-1">
          <span className="block font-mono text-xs text-fg-muted">Why (optional, kept as a comment in the list)</span>
          <input
            id="allowlist-note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="e.g. our SharePoint tenant"
            className="w-full border border-line bg-canvas px-3 py-2 text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          />
        </label>
      </div>
    </Modal>
  )
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

export function IocLookupProvider({ children }) {
  const [lookup, setLookup] = useState(null)
  const [allowlistTarget, setAllowlistTarget] = useState(null)
  const { openMenu } = useContextMenu()
  const { openSearch } = useNavigation()
  const { showToast } = useToast()

  const openIoc = useCallback((type, value) => setLookup({ type, value: String(value) }), [])
  const openAllowlist = useCallback((type, value) => setAllowlistTarget({ type, value: String(value) }), [])
  const close = useCallback(() => setLookup(null), [])

  const iocMenu = useCallback(
    (event, type, value) => {
      const text = String(value)
      const copy = async (content, what) =>
        showToast({ message: (await copyText(content)) ? `${what} copied.` : 'The browser refused to copy.' })
      return openMenu(event, {
        title: `${IOC_TYPES[type]?.label ?? type} · ${text}`,
        items: [
          { label: 'Where else was this seen?', icon: Crosshair, onSelect: () => openIoc(type, text) },
          { label: 'Search for it', icon: Search, hint: 'ctrl k', onSelect: () => openSearch(text) },
          'separator',
          { label: 'Copy', icon: Copy, onSelect: () => copy(text, 'Value') },
          { label: 'Copy defanged', icon: Copy, hint: '[.]', onSelect: () => copy(defang(text), 'Defanged value') },
          'separator',
          { label: 'Add to the allowlist…', icon: ShieldCheck, onSelect: () => openAllowlist(type, text) },
        ],
      })
    },
    [openMenu, openIoc, openSearch, openAllowlist, showToast],
  )

  const value = useMemo(() => ({ openIoc, openAllowlist, iocMenu }), [openIoc, openAllowlist, iocMenu])
  return (
    <IocLookupContext.Provider value={value}>
      {children}
      <WhereSeen lookup={lookup} onClose={close} />
      <AllowlistDialog target={allowlistTarget} onClose={() => setAllowlistTarget(null)} />
    </IocLookupContext.Provider>
  )
}

/** `{ openIoc, openAllowlist, iocMenu }` — see the module comment. */
export function useIocLookup() {
  const ctx = useContext(IocLookupContext)
  if (!ctx) throw new Error('useIocLookup must be used inside <IocLookupProvider>')
  return ctx
}

/** An indicator value that opens "Where seen" when clicked. */
export function IocValue({ type, value, className = '' }) {
  const { openIoc, iocMenu } = useIocLookup()
  if (!type) return <span className={className}>{value}</span>
  return (
    <button
      type="button"
      onClick={(event) => {
        event.stopPropagation()
        openIoc(type, value)
      }}
      onContextMenu={(event) => iocMenu(event, type, value)}
      title="Where else was this seen? (right-click for more)"
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
