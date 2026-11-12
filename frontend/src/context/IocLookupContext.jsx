import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import {
  Boxes,
  Copy,
  Crosshair,
  Globe,
  Link2,
  Maximize2,
  Minimize2,
  RefreshCw,
  Search,
  ShieldCheck,
} from 'lucide-react'
import { Button, Modal } from '../components/ui/index.js'
import IocDetail from '../components/ioc/IocDetail.jsx'
import { onLocationChange, setPath } from '../lib/location.js'
import { ANALYSABLE, analysisActions, iocFromLocation, iocPath } from '../domain/enrichment.js'
import { api } from '../services/api.js'
import { IOC_TYPES, allowlistOptions, defang, indicatorFlaggable } from '../domain/iocs.js'
import { flagItems } from '../components/menu/flagItems.js'
import { useArtifacts } from './ArtifactContext.jsx'
import { useAuth } from './AuthContext.jsx'
import { useContextMenu } from './ContextMenuContext.jsx'
import { useIncidents } from './IncidentContext.jsx'
import { useNavigation } from './NavigationContext.jsx'
import { useSettings } from './SettingsContext.jsx'
import { useToast } from './ToastContext.jsx'

/*
 * Indicators anywhere in the app:
 *   - openIoc(type, value): the indicator's window: its verdict, every source's
 *     answer and every incident it appears in (all analysts'); it can become
 *     a page with its own address (/ioc/<type>?v=<value>);
 *   - openAllowlist(type, value): add it, or a wider entry (its domain, its
 *     /24), to the shared IOC allowlist, with Undo;
 *   - iocMenu(event, type, value): the right-click menu of an indicator.
 * <IocValue> renders a value that does all three.
 */

const IocLookupContext = createContext(null)

/*
 * The indicator's window. It opens over the page; "Open as a page" makes it
 * fill the window and gives it its own address (/ioc/<type>?v=<value>), which
 * can be copied, bookmarked and opened in another tab. Closing the page goes
 * back to where the analyst was.
 */
function IocWindow({ lookup, underPath, onClose, onExpand, onShrink, onAllowlist, onAnalysis, onOpenArtifact }) {
  const { activeIncidentId: loadedIncidentId, selectIncident } = useIncidents()
  // "This incident" is the one on screen: with an artifact or the IoC library in the
  // main area no incident is, and the one it was seen in can be opened.
  const activeIncidentId = /^\/incident\//.test(underPath) ? loadedIncidentId : null
  const { showToast } = useToast()
  if (!lookup) return null
  const copyLink = async () => {
    const link = `${window.location.origin}${iocPath(lookup.type, lookup.value)}`
    showToast({ message: (await copyText(link)) ? 'Link copied.' : 'The browser refused to copy.' })
  }
  const headerButton =
    'inline-flex items-center gap-1 px-1.5 py-1 font-mono text-xs text-fg-muted transition-colors hover:bg-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
  return (
    <Modal
      open
      onClose={onClose}
      title="Indicator"
      maxWidth="max-w-6xl"
      tall
      full={lookup.full}
      actions={
        <>
          <button type="button" onClick={copyLink} className={headerButton}>
            <Link2 className="h-3.5 w-3.5" aria-hidden="true" /> Copy link
          </button>
          <button type="button" onClick={lookup.full ? onShrink : onExpand} className={headerButton}>
            {lookup.full ? (
              <>
                <Minimize2 className="h-3.5 w-3.5" aria-hidden="true" /> Back to a window
              </>
            ) : (
              <>
                <Maximize2 className="h-3.5 w-3.5" aria-hidden="true" /> Open as a page
              </>
            )}
          </button>
        </>
      }
    >
      <IocDetail
        key={`${lookup.type}:${lookup.value}`}
        type={lookup.type}
        value={lookup.value}
        activeIncidentId={activeIncidentId}
        onOpenIncident={(id) => {
          onClose({ keepUrl: true })
          selectIncident(id)
        }}
        onAllowlist={() => onAllowlist(lookup.type, lookup.value)}
        onAnalysis={(action) => onAnalysis(action, lookup.type, lookup.value)}
        onOpenArtifact={onOpenArtifact}
        onNotice={(message) => showToast({ message })}
      />
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

const iocInUrl = () => (typeof window === 'undefined' ? null : iocFromLocation(window.location))

export function IocLookupProvider({ children }) {
  const { isAuthenticated } = useAuth()
  // An indicator opened from its link starts as a page.
  const [lookup, setLookup] = useState(() => {
    const linked = iocInUrl()
    return linked ? { ...linked, full: true } : null
  })
  const [allowlistTarget, setAllowlistTarget] = useState(null)
  const { openMenu, askText } = useContextMenu()
  const { openSearch } = useNavigation()
  const { showToast } = useToast()
  // An indicator is flagged in the incident on screen (none while an artifact is open on its own).
  const { activeIncident, activeIncidentId, toggleFlag, addFlagComment } = useIncidents()
  const { currentId: artifactOpen, scanUrl, openArtifact } = useArtifacts()
  const flagIncident = artifactOpen ? null : activeIncident
  // Where to go back to when the page is closed.
  const returnTo = useRef(null)

  const openIoc = useCallback((type, value) => setLookup({ type, value: String(value), full: false }), [])

  // What Nik analysed itself for an indicator (`analysis` of GET /api/enrichment),
  // remembered so that the right-click menu can say "Open the analysis" at once.
  // Asked when the pointer rests on a value; never needed to act (see runAnalysis).
  const known = useRef(new Map())
  const learn = useCallback(async (type, value) => {
    const key = `${type}\n${value}`
    if (!ANALYSABLE.has(type) || known.current.has(key)) return known.current.get(key)
    known.current.set(key, undefined) // being asked
    try {
      const { analysis } = await api.get(`/enrichment?${new URLSearchParams({ type, value })}`)
      if (known.current.size > 500) known.current.clear()
      known.current.set(key, analysis)
      return analysis
    } catch {
      known.current.delete(key)
      return undefined
    }
  }, [])
  const forget = useCallback((type, value) => known.current.delete(`${type}\n${value}`), [])

  /**
   * Do what an entry of analysisActions() says: open the artifact, visit the
   * address with the isolated browser, or visit it again. Visiting an address
   * Nik already analysed opens that analysis: nothing is visited twice.
   */
  const runAnalysis = useCallback(
    async (action, type, value) => {
      try {
        let artifactId = action.artifact?.id
        if (action.id === 'analyse') {
          showToast({ message: `The isolated browser is visiting ${action.address}…` })
          artifactId = (await scanUrl(action.address)).artifactId
        } else if (action.id === 'rescan') {
          await api.post(`/urls/${action.artifact.id.replace(/^url-/, '')}/rescan`, {})
        }
        forget(type, value)
        setLookup(null)
        returnTo.current = null
        openArtifact(artifactId)
      } catch (err) {
        showToast({ message: err.message })
      }
    },
    [scanUrl, openArtifact, showToast, forget],
  )
  const openAllowlist = useCallback((type, value) => setAllowlistTarget({ type, value: String(value) }), [])

  /** The address the app shows without an indicator page: the open incident, or the start. */
  const basePath = useCallback(
    () => returnTo.current ?? (activeIncidentId ? `/incident/${encodeURIComponent(activeIncidentId)}` : '/'),
    [activeIncidentId],
  )
  const leaveUrl = useCallback(() => {
    if (iocInUrl()) setPath(basePath(), { replace: true })
    returnTo.current = null
  }, [basePath])

  const close = useCallback(
    ({ keepUrl = false } = {}) => {
      if (!keepUrl) leaveUrl()
      setLookup(null)
    },
    [leaveUrl],
  )
  const lookupRef = useRef(lookup)
  lookupRef.current = lookup
  const expand = useCallback(() => {
    const current = lookupRef.current
    if (!current) return
    if (!iocInUrl()) returnTo.current = window.location.pathname + window.location.search
    setPath(iocPath(current.type, current.value), { state: { ioc: true } })
    setLookup({ ...current, full: true })
  }, [])
  const shrink = useCallback(() => {
    // Read before the address changes: leaving it closes a page that is still marked full.
    const current = lookupRef.current
    leaveUrl()
    setLookup(current ? { ...current, full: false } : null)
  }, [leaveUrl])

  // Back and forward: the address decides whether an indicator page is open.
  useEffect(() => {
    const onPopState = () => {
      const linked = iocInUrl()
      setLookup((current) => (linked ? { ...linked, full: true } : current?.full ? null : current))
    }
    return onLocationChange(onPopState)
  }, [])

  const iocMenu = useCallback(
    (event, type, value) => {
      const text = String(value)
      const copy = async (content, what) =>
        showToast({ message: (await copyText(content)) ? `${what} copied.` : 'The browser refused to copy.' })
      return openMenu(event, {
        title: `${IOC_TYPES[type]?.label ?? type} · ${text}`,
        items: [
          ...(flagIncident
            ? [
                ...flagItems({
                  incident: flagIncident,
                  flaggable: indicatorFlaggable(type, text),
                  toggleFlag,
                  addFlagComment,
                  askText,
                  what: 'indicator',
                }),
                'separator',
              ]
            : []),
          ...analysisActions(type, text, known.current.get(`${type}\n${text}`)).map((action) => ({
            label: action.label,
            hint: action.hint,
            icon: action.id === 'open' ? Boxes : action.id === 'rescan' ? RefreshCw : Globe,
            onSelect: () => runAnalysis(action, type, text),
          })),
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
    [
      openMenu,
      openIoc,
      openSearch,
      openAllowlist,
      showToast,
      flagIncident,
      toggleFlag,
      addFlagComment,
      askText,
      runAnalysis,
    ],
  )

  const value = useMemo(
    () => ({ openIoc, openAllowlist, iocMenu, learn, runAnalysis }),
    [openIoc, openAllowlist, iocMenu, learn, runAnalysis],
  )
  return (
    <IocLookupContext.Provider value={value}>
      {children}
      {isAuthenticated && (
        <IocWindow
          lookup={lookup}
          underPath={lookup?.full ? (returnTo.current ?? '') : window.location.pathname}
          onClose={close}
          onExpand={expand}
          onShrink={shrink}
          onAllowlist={openAllowlist}
          onAnalysis={runAnalysis}
          onOpenArtifact={(id) => {
            setLookup(null)
            returnTo.current = null
            openArtifact(id)
          }}
        />
      )}
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
/**
 * `ownMenu={false}` inside a row that has a menu of its own: the right-click
 * (and F, C) then act on the row, wherever in it the pointer is.
 */
export function IocValue({ type, value, className = '', ownMenu = true }) {
  const { openIoc, iocMenu, learn } = useIocLookup()
  const hover = useRef(null)
  if (!type) return <span className={className}>{value}</span>
  // The pointer resting on a value: learn whether Nik analysed it, for the menu.
  const rest = () => {
    hover.current = setTimeout(() => learn(type, String(value)), 200)
  }
  return (
    <button
      type="button"
      onClick={(event) => {
        event.stopPropagation()
        openIoc(type, value)
      }}
      onContextMenu={ownMenu ? (event) => iocMenu(event, type, value) : undefined}
      onMouseEnter={rest}
      onMouseLeave={() => clearTimeout(hover.current)}
      onFocus={() => learn(type, String(value))}
      title="Reputation and where seen (right-click: analyse, copy, more)"
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
