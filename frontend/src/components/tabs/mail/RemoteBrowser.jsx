import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Globe,
  Hand,
  Lock,
  Maximize2,
  Minimize2,
  RotateCw,
  Send,
  WifiOff,
  X,
} from 'lucide-react'
import { AsciiSkull, Badge, Button, Modal } from '../../ui/index.js'
import { api } from '../../../services/api.js'
import { BROWSER_KEYS, browserViewport, fitInside, toPagePoint } from '../../../domain/mail.js'
import RequestLog from '../network/RequestLog.jsx'

/*
 * The isolated browser. The page runs in Chromium inside the `browser`
 * worker's container; this window only shows its screenshot. Clicks,
 * typing, keys and the mouse wheel are sent to the worker and replayed
 * there, so nothing of the page (scripts, downloads, requests) reaches the
 * analyst's machine.
 *
 * Network, chosen before opening (OpenBrowserDialog): none by default (only
 * the attachment loads); with network the page reaches the internet, never
 * private addresses; submissions are held until the analyst sends them. The
 * Network panel lists every request (DevTools-like); opened from an incident,
 * the log is kept there and becomes a capture in Network Analysis when the
 * window closes. Escape closes the window.
 *
 * Tabs: a window the page opens (a sign-in pop-up, a target=_blank link) is a
 * tab of the session, shown at once; the tab bar appears with the second one
 * and switches between them. A tab that closes itself returns to its opener.
 *
 * Size: the page is drawn at the size of the space this window gives it, so a
 * large monitor shows a large page, at one screenshot pixel per screen pixel.
 * The window fills most of the screen, and the Full screen button all of it.
 */

export function OpenBrowserDialog({ target, onCancel, onOpen }) {
  const [network, setNetwork] = useState(false)
  useEffect(() => setNetwork(false), [target])
  if (!target) return null
  const isUrl = Boolean(target.url)
  return (
    <Modal
      open
      onClose={onCancel}
      title="Open in the isolated browser"
      footer={
        <>
          <Button variant="secondary" onClick={onCancel}>
            Cancel
          </Button>
          <Button icon={Globe} onClick={() => onOpen({ ...target, network })}>
            Open
          </Button>
        </>
      }
    >
      <div className="space-y-3 font-mono text-sm">
        <p className="break-all text-fg">{target.label}</p>
        <fieldset className="space-y-2">
          <legend className="sr-only">Network</legend>
          {[
            {
              value: false,
              title: 'No network (recommended)',
              hint: isUrl
                ? 'Nothing is fetched: a link opened this way shows only that it was blocked.'
                : 'Only the attachment loads; every request it makes (images, scripts, forms, links) is refused.',
            },
            {
              value: true,
              title: 'Allow internet for this session',
              hint: 'The page and its redirects load from the internet through the server, never from private addresses. The sites see the company IP. Recorded in the audit log.',
            },
          ].map((option) => (
            <label
              key={String(option.value)}
              className={[
                'grid cursor-pointer grid-cols-[1rem_minmax(0,1fr)] gap-x-3 gap-y-1 border px-3 py-2.5',
                network === option.value ? 'border-accent-strong bg-accent-soft' : 'border-line',
              ].join(' ')}
            >
              <input
                type="radio"
                name="browser-network"
                className="mt-1 accent-accent"
                checked={network === option.value}
                onChange={() => setNetwork(option.value)}
              />
              <span className="font-semibold text-fg">{option.title}</span>
              <span className="col-start-2 text-xs text-fg-muted">{option.hint}</span>
            </label>
          ))}
        </fieldset>
        {network && (
          <p className="flex gap-2 border-l-2 border-med-line bg-med-soft px-3 py-2 text-xs text-med-fg">
            <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden="true" />
            Live phishing pages may log the visit and change what they serve. Never type real credentials.
          </p>
        )}
      </div>
    </Modal>
  )
}

const REFRESH_MS = 4000
// The page follows the window a moment after it stops changing size.
const RESIZE_SETTLE_MS = 300

/** The space the dialog will give the page, guessed from the window before the dialog is drawn. */
const guessViewport = () => browserViewport(window.innerWidth * 0.98 - 44, window.innerHeight * 0.96 - 190)

export default function RemoteBrowser({ request, onClose }) {
  const [state, setState] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [confirmRelease, setConfirmRelease] = useState(false)
  const [address, setAddress] = useState('')
  const [fullscreen, setFullscreen] = useState(false)
  // The space available to the page, in CSS pixels.
  const [box, setBox] = useState(null)
  const sessionRef = useRef(null)
  const activeTabRef = useRef(null)
  const queue = useRef(Promise.resolve())
  const typed = useRef('')
  const typeTimer = useRef(null)
  const wheel = useRef(0)
  const wheelTimer = useRef(null)
  const imageRef = useRef(null)
  const frameRef = useRef(null)
  const viewRef = useRef(null)

  /** Keep the state, and follow the address when the session moved to another tab by itself. */
  const accept = useCallback((res, { followAddress = true } = {}) => {
    const active = res.tabs?.find((tab) => tab.active)?.id ?? null
    const moved = active !== activeTabRef.current
    activeTabRef.current = active
    setState((prev) => ({ ...res, captureId: res.captureId ?? prev?.captureId }))
    if (followAddress || moved) setAddress(res.url)
  }, [])

  // Open the session; close it when the window goes away.
  useEffect(() => {
    if (!request) return undefined
    let cancelled = false
    setState(null)
    setError(null)
    activeTabRef.current = null
    const source = request.url ? { url: request.url } : { mail: request.sha256, path: request.path }
    const body = {
      ...source,
      network: request.network,
      ...(request.incident ? { incident: request.incident } : {}),
      ...guessViewport(),
    }
    api
      .post('/browser/sessions', body)
      .then((res) => {
        if (cancelled) {
          api.del(`/browser/sessions/${res.id}`).catch(() => {})
          return
        }
        sessionRef.current = res.id
        accept(res)
      })
      .catch((err) => !cancelled && setError(err.message))
    return () => {
      cancelled = true
      const id = sessionRef.current
      sessionRef.current = null
      if (id) api.del(`/browser/sessions/${id}`).catch(() => {})
    }
  }, [request, accept])

  const send = useCallback(
    (action) => {
      queue.current = queue.current.then(async () => {
        const id = sessionRef.current
        if (!id) return
        setBusy(true)
        try {
          const res = await api.post(`/browser/sessions/${id}/action`, action)
          // A refresh must not overwrite an address being typed.
          accept(res, { followAddress: action.type !== 'refresh' && action.type !== 'resize' })
          setError(null)
        } catch (err) {
          setError(err.message)
        } finally {
          setBusy(false)
        }
      })
      return queue.current
    },
    [accept],
  )

  // The Network panel: the session's requests, refreshed while it is open.
  const [showNetwork, setShowNetwork] = useState(false)
  const [entries, setEntries] = useState([])
  const sessionId = state?.id
  useEffect(() => {
    if (!showNetwork || !sessionId) return undefined
    let cancelled = false
    const load = () =>
      api
        .get(`/browser/sessions/${sessionId}/network`)
        .then((res) => !cancelled && setEntries(res.entries))
        .catch(() => {})
    load()
    const timer = setInterval(load, REFRESH_MS)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [showNetwork, sessionId, state?.log?.requests])
  const loadEntry = useCallback(
    (id) =>
      state?.captureId
        ? api.get(`/captures/${state.captureId}/requests/${id}`)
        : Promise.reject(new Error('Open the session from an incident to keep its requests.')),
    [state?.captureId],
  )

  // Pages change by themselves (redirects, timers, a pop-up): refresh the screenshot.
  useEffect(() => {
    if (!state) return undefined
    const timer = setInterval(() => {
      if (!busy && document.visibilityState === 'visible') send({ type: 'refresh' })
    }, REFRESH_MS)
    return () => clearInterval(timer)
  }, [state, busy, send])

  // The space the page has: measured, and measured again whenever it changes.
  const hasState = Boolean(state)
  useEffect(() => {
    const element = viewRef.current
    if (!element || typeof ResizeObserver === 'undefined') return undefined
    const observer = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect
      setBox({ width, height })
    })
    observer.observe(element)
    return () => observer.disconnect()
  }, [hasState])

  // Ask the worker to draw the pages at that size, once the window has settled.
  const wanted = box ? browserViewport(box.width, box.height) : null
  const wantedWidth = wanted?.width
  const wantedHeight = wanted?.height
  const drawnWidth = state?.width
  const drawnHeight = state?.height
  useEffect(() => {
    if (!wantedWidth || !drawnWidth) return undefined
    if (wantedWidth === drawnWidth && wantedHeight === drawnHeight) return undefined
    const timer = setTimeout(() => send({ type: 'resize', width: wantedWidth, height: wantedHeight }), RESIZE_SETTLE_MS)
    return () => clearTimeout(timer)
  }, [wantedWidth, wantedHeight, drawnWidth, drawnHeight, send])

  // Full screen: the whole window (toolbar, tabs, page) fills the monitor.
  useEffect(() => {
    const onChange = () => setFullscreen(document.fullscreenElement === frameRef.current)
    document.addEventListener('fullscreenchange', onChange)
    return () => document.removeEventListener('fullscreenchange', onChange)
  }, [])
  const toggleFullscreen = () => {
    if (document.fullscreenElement) document.exitFullscreen?.()
    else frameRef.current?.requestFullscreen?.().catch(() => setError('This browser refused the full screen.'))
  }

  const flushTyping = useCallback(() => {
    clearTimeout(typeTimer.current)
    if (typed.current) {
      const text = typed.current
      typed.current = ''
      send({ type: 'type', text })
    }
  }, [send])

  const onKeyDown = (event) => {
    if (event.key === 'Escape' || event.ctrlKey || event.metaKey || event.altKey) return
    if (event.key.length === 1) {
      event.preventDefault()
      typed.current += event.key
      clearTimeout(typeTimer.current)
      typeTimer.current = setTimeout(flushTyping, 350)
    } else if (BROWSER_KEYS.has(event.key)) {
      event.preventDefault()
      flushTyping()
      send({ type: 'key', key: event.key === 'Tab' && event.shiftKey ? 'Shift+Tab' : event.key })
    }
  }

  const onWheel = (event) => {
    wheel.current += event.deltaY
    clearTimeout(wheelTimer.current)
    wheelTimer.current = setTimeout(() => {
      const dy = wheel.current
      wheel.current = 0
      if (dy) send({ type: 'scroll', dy })
    }, 200)
  }

  const onClick = (event) => {
    if (!state || !imageRef.current) return
    flushTyping()
    const point = toPagePoint(
      event.clientX,
      event.clientY,
      imageRef.current.getBoundingClientRect(),
      state.width,
      state.height,
    )
    send({ type: event.detail === 2 ? 'dblclick' : 'click', ...point })
    event.currentTarget.focus()
  }

  if (!request) return null
  const title = state?.title || request.label
  const tabs = state?.tabs ?? []
  // The picture at its own size when it fits, scaled down (never up) when the space is smaller.
  const drawn = state && box ? fitInside(state.width, state.height, box.width, box.height) : null

  return (
    <Modal
      open
      // Escape leaves the full screen first; only then does it close the window.
      onClose={() => !document.fullscreenElement && onClose()}
      title={`Isolated browser · ${title}`}
      maxWidth="max-w-[98vw]"
      tall
    >
      <div
        ref={frameRef}
        className={[
          'flex flex-col gap-2 bg-panel',
          fullscreen ? 'h-screen w-screen p-3' : 'h-[calc(96vh-7.5rem)] min-h-[24rem]',
        ].join(' ')}
      >
        <div className="flex shrink-0 flex-wrap items-center gap-1.5">
          <Button
            variant="ghost"
            size="xs"
            icon={ArrowLeft}
            aria-label="Back"
            onClick={() => send({ type: 'back' })}
            disabled={!state}
          />
          <Button
            variant="ghost"
            size="xs"
            icon={ArrowRight}
            aria-label="Forward"
            onClick={() => send({ type: 'forward' })}
            disabled={!state}
          />
          <Button
            variant="ghost"
            size="xs"
            icon={RotateCw}
            aria-label="Reload"
            onClick={() => send({ type: 'reload' })}
            disabled={!state}
          />
          <form
            className="min-w-0 flex-1"
            onSubmit={(event) => {
              event.preventDefault()
              if (address.trim()) send({ type: 'navigate', url: address.trim() })
            }}
          >
            <input
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              placeholder={state?.attachment ? 'the attachment (type an address to go elsewhere)' : 'https://…'}
              aria-label="Address"
              disabled={!state}
              className="w-full border border-line bg-canvas px-2 py-1 font-mono text-xs text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            />
          </form>
          {state &&
            (state.network ? (
              <Badge color="amber" title="This session reaches the internet (never private addresses)">
                <Globe className="h-3 w-3" /> network
              </Badge>
            ) : (
              <Badge color="emerald" title="Nothing leaves the worker">
                <WifiOff className="h-3 w-3" /> no network
              </Badge>
            ))}
          {state?.network && (
            <Button
              variant={state.releasePosts ? 'secondary' : 'ghost'}
              size="xs"
              icon={state.releasePosts ? Send : Hand}
              onClick={() =>
                state.releasePosts ? send({ type: 'policy', releasePosts: false }) : setConfirmRelease(true)
              }
              title="Submissions (form posts, fetch POST…) are held by default: recorded, not sent"
            >
              {state.releasePosts ? 'Submissions sent' : 'Submissions held'}
            </Button>
          )}
          {state && (
            <Button
              variant={showNetwork ? 'secondary' : 'ghost'}
              size="xs"
              icon={Activity}
              onClick={() => setShowNetwork((v) => !v)}
              aria-pressed={showNetwork}
            >
              Network · {state.log?.requests ?? 0}
            </Button>
          )}
          <Button
            variant="ghost"
            size="xs"
            icon={fullscreen ? Minimize2 : Maximize2}
            onClick={toggleFullscreen}
            aria-pressed={fullscreen}
            aria-label={fullscreen ? 'Leave full screen' : 'Full screen'}
            title={fullscreen ? 'Leave full screen (Esc)' : 'Full screen'}
          />
          {busy && <span className="font-mono text-[11px] text-fg-muted">…</span>}
        </div>

        {tabs.length > 1 && (
          <div role="tablist" aria-label="Tabs of the session" className="flex shrink-0 gap-1 overflow-x-auto">
            {tabs.map((tab) => {
              const name = tab.title || tab.url || 'new tab'
              return (
                <span
                  key={tab.id}
                  className={[
                    'flex min-w-0 max-w-[18rem] shrink-0 items-center border font-mono text-xs',
                    tab.active ? 'border-accent-strong bg-accent-soft text-fg' : 'border-line text-fg-muted',
                  ].join(' ')}
                >
                  <button
                    type="button"
                    role="tab"
                    aria-selected={tab.active}
                    title={tab.url || name}
                    onClick={() => !tab.active && send({ type: 'tab', id: tab.id })}
                    className="min-w-0 truncate px-2 py-1 hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    {name}
                  </button>
                  <button
                    type="button"
                    aria-label={`Close the tab ${name}`}
                    title="Close this tab"
                    onClick={() => send({ type: 'closeTab', id: tab.id })}
                    className="shrink-0 px-1 py-1 text-fg-muted hover:text-high focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    <X className="h-3 w-3" aria-hidden="true" />
                  </button>
                </span>
              )
            })}
          </div>
        )}

        <Modal
          open={confirmRelease}
          onClose={() => setConfirmRelease(false)}
          title="Send the page's submissions?"
          footer={
            <>
              <Button variant="secondary" onClick={() => setConfirmRelease(false)}>
                Keep holding
              </Button>
              <Button
                onClick={() => {
                  setConfirmRelease(false)
                  send({ type: 'policy', releasePosts: true })
                }}
              >
                Send submissions
              </Button>
            </>
          }
        >
          <p className="flex gap-2 border-l-2 border-med-line bg-med-soft px-3 py-2 font-mono text-xs text-med-fg">
            <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden="true" />
            From now on, what the page submits reaches the site: use invented credentials only. This is recorded in the
            audit log.
          </p>
        </Modal>

        {error && (
          <p role="alert" className="shrink-0 font-mono text-xs text-high">
            {error}
          </p>
        )}
        {!state && !error && (
          <div aria-busy="true" className="flex flex-1 flex-col items-center justify-center gap-3 font-mono">
            <AsciiSkull preset="medium" />
            <p role="status" className="text-sm text-fg-muted">
              Opening the page in the isolated browser…
            </p>
          </div>
        )}
        {state && (
          // The space left for the page: what the worker is asked to draw it at.
          <div ref={viewRef} className="flex min-h-0 flex-1 items-start justify-center overflow-hidden">
            <div
              role="application"
              aria-label="Remote page: click, type and scroll here"
              tabIndex={0}
              onKeyDown={onKeyDown}
              onWheel={onWheel}
              onClick={onClick}
              className="cursor-crosshair border border-line bg-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <img
                ref={imageRef}
                src={`data:image/jpeg;base64,${state.screenshot}`}
                alt={`Screenshot of ${title}`}
                draggable={false}
                width={drawn?.width}
                height={drawn?.height}
                className="block select-none"
              />
            </div>
          </div>
        )}
        {state && showNetwork && (
          <div className="max-h-[40%] shrink-0 overflow-y-auto">
            <RequestLog entries={entries} loadEntry={loadEntry} live />
          </div>
        )}
        {state && (
          <div className="flex shrink-0 flex-wrap items-start justify-between gap-2 font-mono text-[11px] text-fg-muted">
            <span className="flex items-center gap-1">
              <Lock className="h-3 w-3" aria-hidden="true" />
              Runs in the worker; you see a picture ({state.width}×{state.height}). {state.blocked} request
              {state.blocked === 1 ? '' : 's'} refused
              {state.log?.held ? `, ${state.log.held} submission${state.log.held === 1 ? '' : 's'} held` : ''}.
              {state.captureId ? ' The log is kept in the incident (Network Analysis).' : ''}
            </span>
            {state.events.length > 0 && (
              <ul className="max-w-xl space-y-0.5 text-right">
                {state.events
                  .slice(-4)
                  .reverse()
                  .map((e, i) => (
                    <li key={i} className={e.kind === 'blocked' || e.kind === 'download' ? 'text-med' : ''}>
                      {e.text}
                    </li>
                  ))}
              </ul>
            )}
          </div>
        )}
      </div>
    </Modal>
  )
}
