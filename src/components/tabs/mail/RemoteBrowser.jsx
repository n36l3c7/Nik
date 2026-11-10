import { useCallback, useEffect, useRef, useState } from 'react'
import { AlertTriangle, ArrowLeft, ArrowRight, Globe, Lock, RotateCw, WifiOff } from 'lucide-react'
import { AsciiSkull, Badge, Button, Modal } from '../../ui/index.js'
import { api } from '../../../services/api.js'
import { BROWSER_KEYS, toPagePoint } from '../../../utils/mail.js'

/*
 * The isolated browser. The page runs in Chromium inside the `browser`
 * worker's container; this window only shows its screenshot. Clicks,
 * typing, keys and the mouse wheel are sent to the worker and replayed
 * there, so nothing of the page (scripts, downloads, requests) reaches the
 * analyst's machine.
 *
 * Network, chosen before opening (OpenBrowserDialog): none by default (only
 * the attachment loads); with network the page reaches the internet, never
 * private addresses. Escape closes the window.
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

export default function RemoteBrowser({ request, onClose }) {
  const [state, setState] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [address, setAddress] = useState('')
  const sessionRef = useRef(null)
  const queue = useRef(Promise.resolve())
  const typed = useRef('')
  const typeTimer = useRef(null)
  const wheel = useRef(0)
  const wheelTimer = useRef(null)
  const imageRef = useRef(null)

  // Open the session; close it when the window goes away.
  useEffect(() => {
    if (!request) return undefined
    let cancelled = false
    setState(null)
    setError(null)
    const body = request.url
      ? { url: request.url, network: request.network }
      : { mail: request.sha256, path: request.path, network: request.network }
    api
      .post('/browser/sessions', body)
      .then((res) => {
        if (cancelled) {
          api.del(`/browser/sessions/${res.id}`).catch(() => {})
          return
        }
        sessionRef.current = res.id
        setState(res)
        setAddress(res.url)
      })
      .catch((err) => !cancelled && setError(err.message))
    return () => {
      cancelled = true
      const id = sessionRef.current
      sessionRef.current = null
      if (id) api.del(`/browser/sessions/${id}`).catch(() => {})
    }
  }, [request])

  const send = useCallback((action) => {
    queue.current = queue.current.then(async () => {
      const id = sessionRef.current
      if (!id) return
      setBusy(true)
      try {
        const res = await api.post(`/browser/sessions/${id}/action`, action)
        setState(res)
        if (action.type !== 'refresh') setAddress(res.url)
        setError(null)
      } catch (err) {
        setError(err.message)
      } finally {
        setBusy(false)
      }
    })
    return queue.current
  }, [])

  // Pages change by themselves (redirects, timers): refresh the screenshot.
  useEffect(() => {
    if (!state) return undefined
    const timer = setInterval(() => {
      if (!busy && document.visibilityState === 'visible') send({ type: 'refresh' })
    }, REFRESH_MS)
    return () => clearInterval(timer)
  }, [state, busy, send])

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

  return (
    <Modal open onClose={onClose} title={`Isolated browser · ${title}`} maxWidth="max-w-6xl">
      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-1.5">
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
          {busy && <span className="font-mono text-[11px] text-fg-muted">…</span>}
        </div>

        {error && (
          <p role="alert" className="font-mono text-xs text-high">
            {error}
          </p>
        )}
        {!state && !error && (
          <div aria-busy="true" className="flex flex-col items-center gap-3 py-10 font-mono">
            <AsciiSkull preset="medium" />
            <p role="status" className="text-sm text-fg-muted">
              Opening the page in the isolated browser…
            </p>
          </div>
        )}
        {state && (
          <div
            role="application"
            aria-label="Remote page: click, type and scroll here"
            tabIndex={0}
            onKeyDown={onKeyDown}
            onWheel={onWheel}
            onClick={onClick}
            className="relative max-h-[72vh] cursor-crosshair overflow-hidden border border-line bg-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <img
              ref={imageRef}
              src={`data:image/jpeg;base64,${state.screenshot}`}
              alt={`Screenshot of ${title}`}
              draggable={false}
              className="block w-full select-none"
            />
          </div>
        )}
        {state && (
          <div className="flex flex-wrap items-start justify-between gap-2 font-mono text-[11px] text-fg-muted">
            <span className="flex items-center gap-1">
              <Lock className="h-3 w-3" aria-hidden="true" />
              Runs in the worker; you see a picture. {state.blocked} request{state.blocked === 1 ? '' : 's'} refused.
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
