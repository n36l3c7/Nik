import { useEffect, useMemo, useRef, useState } from 'react'
import { Bug, ChevronRight, Crosshair, FolderOpen, Loader2, StickyNote, Zap } from 'lucide-react'
import { Badge } from '../ui/index.js'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useIocLookup } from '../../context/IocLookupContext.jsx'
import { useSocEngine } from '../../context/SettingsContext.jsx'
import { api } from '../../services/api.js'
import { IOC_TYPES } from '../../domain/iocs.js'
import { matchActions, searchIncident, tabForSource } from '../../domain/search.js'
import { buildTimelineEvents, TIMELINE_SOURCE_META } from '../../domain/timeline.js'
import { formatDateTime } from '../../lib/time.js'
import { useLayer } from '../../lib/layers.js'

/*
 * Global search palette (Ctrl/Cmd+K or "/"): a `nik>` prompt that searches
 * incidents, indicators from every incident and samples on the server, plus
 * the open incident's events, notes and samples in memory. A query starting
 * with ">" lists actions. ↑/↓ move, Enter runs, Esc closes.
 */

const DEBOUNCE_MS = 200
const NO_RESULTS = { incidents: [], iocs: [], samples: [] }

function Group({ title, children }) {
  return (
    <div className="py-1">
      <p className="px-4 pb-1 pt-2 font-mono text-[10px] uppercase tracking-wider text-fg-subtle">{title}</p>
      <ul>{children}</ul>
    </div>
  )
}

export default function CommandPalette({ open, onClose, actions, onOpenTab, initialQuery = '' }) {
  const { activeIncident, selectIncident } = useIncidents()
  const { openIoc } = useIocLookup()
  const engine = useSocEngine()
  const listRef = useRef(null)
  const [query, setQuery] = useState('')
  const [remote, setRemote] = useState({ loading: false, data: NO_RESULTS, error: null })
  const [cursor, setCursor] = useState(0)

  const isAction = query.trimStart().startsWith('>')
  const text = query.trim()

  useEffect(() => {
    if (!open) return
    setQuery(initialQuery)
    setCursor(0)
    setRemote({ loading: false, data: NO_RESULTS, error: null })
    // The query is seeded once per opening.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  // Server search, debounced; aborted when the query changes.
  useEffect(() => {
    if (!open || isAction || text.length < 2) {
      setRemote({ loading: false, data: NO_RESULTS, error: null })
      return undefined
    }
    const controller = new AbortController()
    setRemote((r) => ({ ...r, loading: true }))
    const timer = setTimeout(() => {
      api
        .get(`/search?${new URLSearchParams({ q: text, limit: '6' })}`, { signal: controller.signal })
        .then((data) => setRemote({ loading: false, data: { ...NO_RESULTS, ...data }, error: null }))
        .catch((err) => {
          if (!controller.signal.aborted) setRemote({ loading: false, data: NO_RESULTS, error: err?.message })
        })
    }, DEBOUNCE_MS)
    return () => {
      clearTimeout(timer)
      controller.abort()
    }
  }, [open, isAction, text])

  // The open incident's events (built only while the palette is open).
  const events = useMemo(
    () => (open && activeIncident ? buildTimelineEvents(activeIncident.data, engine) : []),
    [open, activeIncident, engine],
  )
  const local = useMemo(
    () =>
      isAction || text.length < 2
        ? { events: [], notes: [], samples: [] }
        : searchIncident({ incident: activeIncident, events, query: text, limit: 6 }),
    [isAction, text, activeIncident, events],
  )

  const groups = useMemo(() => {
    const run = (fn) => () => {
      onClose()
      fn()
    }
    if (isAction || text.length === 0) {
      const list = isAction ? matchActions(actions, text) : actions
      return [
        {
          title: isAction ? 'Actions' : 'Actions — type to search, or ">" for actions only',
          items: list.map((action) => ({
            key: action.id,
            icon: action.icon ?? Zap,
            primary: action.label,
            secondary: action.hint,
            run: run(action.run),
          })),
        },
      ]
    }
    const out = []
    if (remote.data.incidents.length) {
      out.push({
        title: 'Incidents',
        items: remote.data.incidents.map((incident) => ({
          key: `incident:${incident.id}`,
          icon: FolderOpen,
          primary: incident.name || incident.id,
          secondary: [incident.username, incident.os].filter(Boolean).join(' · '),
          run: run(() => selectIncident(incident.id)),
        })),
      })
    }
    if (remote.data.iocs.length) {
      out.push({
        title: 'Indicators — all incidents',
        items: remote.data.iocs.map((ioc) => ({
          key: `ioc:${ioc.type}:${ioc.value}`,
          icon: Crosshair,
          badge: IOC_TYPES[ioc.type]?.short ?? ioc.type,
          badgeColor: IOC_TYPES[ioc.type]?.color,
          primary: ioc.value,
          secondary: `${ioc.incidents} ${ioc.incidents === 1 ? 'incident' : 'incidents'}`,
          run: run(() => openIoc(ioc.type, ioc.value)),
        })),
      })
    }
    const samples = [
      ...local.samples.map((s) => ({ sha256: s.sha256, label: s.fileName, detail: s.type?.label })),
      ...remote.data.samples
        .filter((s) => !local.samples.some((l) => l.sha256 === s.sha256))
        .map((s) => ({ sha256: s.sha256, label: `${s.sha256.slice(0, 16)}…`, detail: s.type })),
    ]
    if (samples.length) {
      out.push({
        title: 'Samples',
        items: samples.map((sample) => ({
          key: `sample:${sample.sha256}`,
          icon: Bug,
          primary: sample.label,
          secondary: sample.detail,
          run: run(() => openIoc('sha256', sample.sha256)),
        })),
      })
    }
    if (local.events.length) {
      out.push({
        title: 'Events — this incident',
        items: local.events.map((event) => ({
          key: `event:${event.id}`,
          icon: ChevronRight,
          badge: event.sourceLabel,
          badgeColor: TIMELINE_SOURCE_META[event.sourceType]?.color,
          primary: event.label,
          secondary: `${formatDateTime(event.time)}${event.detail ? ` · ${event.detail}` : ''}`,
          run: run(() => onOpenTab(tabForSource(event.sourceType))),
        })),
      })
    }
    if (local.notes.length) {
      out.push({
        title: 'Notes — this incident',
        items: local.notes.map((note) => ({
          key: `note:${note.id}`,
          icon: StickyNote,
          primary: note.text,
          secondary: note.author,
          run: run(() => onOpenTab('summary')),
        })),
      })
    }
    return out
  }, [isAction, text, actions, remote.data, local, onClose, selectIncident, openIoc, onOpenTab])

  const flat = useMemo(() => groups.flatMap((group) => group.items), [groups])

  useEffect(() => setCursor(0), [query])
  useEffect(() => {
    listRef.current?.querySelector('[data-active="true"]')?.scrollIntoView({ block: 'nearest' })
  }, [cursor])

  // Escape closes it, Tab stays in it, and the focus returns to where it was.
  const dialogRef = useRef(null)
  useLayer(dialogRef, { open, onClose })

  if (!open) return null

  const onKeyDown = (event) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      setCursor((c) => (flat.length ? (c + 1) % flat.length : 0))
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      setCursor((c) => (flat.length ? (c - 1 + flat.length) % flat.length : 0))
    } else if (event.key === 'Enter') {
      event.preventDefault()
      flat[cursor]?.run()
    }
  }

  let index = -1
  const searching = !isAction && text.length >= 2
  return (
    <div
      ref={dialogRef}
      role="dialog"
      aria-modal="true"
      aria-label="Search"
      className="fixed inset-0 z-50 flex items-start justify-center bg-sunken/70 px-4 pt-[12vh] backdrop-blur-sm"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div className="flex max-h-[70vh] w-full max-w-2xl flex-col overflow-hidden border border-line bg-panel shadow-2xl">
        <div className="flex items-center gap-2 border-b border-line px-4 py-3 font-mono">
          <span className="text-sm text-accent" aria-hidden="true">
            nik&gt;
          </span>
          <input
            // The input mounts with the dialog: focused at once, so the keys
            // typed right after Ctrl/Cmd+K land in it.
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="search incidents, indicators, samples, events… or > for actions"
            aria-label="Search"
            aria-controls="palette-results"
            aria-activedescendant={flat[cursor] ? `palette-${flat[cursor].key}` : undefined}
            className="min-w-0 flex-1 bg-transparent text-sm text-fg placeholder:text-fg-subtle focus:outline-none"
            spellCheck={false}
            autoComplete="off"
          />
          {remote.loading && <Loader2 className="h-4 w-4 animate-spin text-fg-muted" aria-label="Searching" />}
          <kbd className="border border-line px-1.5 font-mono text-[10px] text-fg-subtle">esc</kbd>
        </div>
        <div id="palette-results" ref={listRef} role="listbox" className="overflow-y-auto">
          {groups.map((group) => (
            <Group key={group.title} title={group.title}>
              {group.items.map((item) => {
                index += 1
                const active = index === cursor
                const Icon = item.icon
                const position = index
                return (
                  <li
                    key={item.key}
                    id={`palette-${item.key}`}
                    role="option"
                    aria-selected={active}
                    data-active={active}
                    onMouseMove={() => setCursor(position)}
                    onClick={item.run}
                    className={[
                      'flex cursor-pointer items-center gap-3 px-4 py-2',
                      active ? 'bg-accent-soft' : 'hover:bg-raised',
                    ].join(' ')}
                  >
                    <Icon className={`h-4 w-4 shrink-0 ${active ? 'text-accent' : 'text-fg-muted'}`} />
                    {item.badge && <Badge color={item.badgeColor ?? 'slate'}>{item.badge}</Badge>}
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-mono text-sm text-fg">{item.primary}</span>
                      {item.secondary && (
                        <span className="block truncate text-[11px] text-fg-muted">{item.secondary}</span>
                      )}
                    </span>
                  </li>
                )
              })}
            </Group>
          ))}
          {searching && !remote.loading && flat.length === 0 && (
            <p className="px-4 py-6 text-center font-mono text-sm text-fg-muted">
              {remote.error ? remote.error : `no match for "${text}"`}
            </p>
          )}
        </div>
        <div className="flex flex-wrap gap-x-4 gap-y-1 border-t border-line px-4 py-2 font-mono text-[10px] text-fg-subtle">
          <span>↑↓ move</span>
          <span>↵ open</span>
          <span>&gt; actions</span>
          <span>indicators: every incident · events and notes: open incident</span>
        </div>
      </div>
    </div>
  )
}
