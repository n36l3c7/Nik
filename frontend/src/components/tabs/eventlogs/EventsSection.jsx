/*
 * The events of the event-log sources, read from the server a page at a time (ServerTable over
 * /records, kind eventlog). Every event the worker kept is here, not only the ones Nik knew by id.
 * Filters are the API's (domain/evidenceQuery.js); a row is flagged and annotated through the marks
 * of the evidence API, and its "Source" opens the original behind it.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { CalendarClock, FileSearch, Flag, Star, StickyNote } from 'lucide-react'
import { Button, Select, ServerTable } from '../../ui/index.js'
import SourceViewer from '../../evidence/SourceViewer.jsx'
import StackPanel from '../../evidence/StackPanel.jsx'
import DateTimeRangeFilter from '../../ui/DateTimeRangeFilter.jsx'
import { useContextMenu } from '../../../context/ContextMenuContext.jsx'
import { useToast } from '../../../context/ToastContext.jsx'
import { useItemMenu } from '../../menu/useRowMenu.js'
import { getChannel, getEventDefinition } from '../../../config/eventLogs.js'
import { withFilter } from '../../../domain/serverTable.js'
import {
  EVENTLOG_KIND,
  flaggedOf,
  levelText,
  neighbourRecords,
  sourceOfRecord,
} from '../../../domain/eventLogSources.js'
import { formatDateTime } from '../../../lib/time.js'
import { evidence } from '../../../services/api.js'

const BASE = { kind: EVENTLOG_KIND }
const NO_OPTIONS = []
// The event's own level is in its data; the record's `level` is the one of its detections (stage 5).
const FIELDS = ['level']
const FLAG_HIGHLIGHT = 'bg-accent-soft border-l-2 border-l-accent-strong'
const INPUT =
  'border border-line bg-canvas px-2 py-1.5 font-mono text-[13px] text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/** The range of the incident's suspicious window as the filters `from` and `to`. */
const incidentRange = (incident) =>
  withFilter(withFilter({}, 'from', incident.suspiciousStart ?? null), 'to', incident.suspiciousEnd ?? null)

/** A text filter: typed freely, applied on Enter or when the field is left. */
function FilterInput({ label, value, onCommit, width = 'w-28', inputMode }) {
  const [text, setText] = useState(value)
  useEffect(() => setText(value), [value])
  const commit = () => {
    if (text.trim() !== value) onCommit(text.trim())
  }
  return (
    <label className="inline-flex items-center gap-2">
      <span className="whitespace-nowrap font-mono text-xs text-fg-muted">{label}</span>
      <input
        value={text}
        inputMode={inputMode}
        onChange={(event) => setText(event.target.value)}
        onBlur={commit}
        onKeyDown={(event) => event.key === 'Enter' && commit()}
        className={`${INPUT} ${width}`}
      />
    </label>
  )
}

/** The values of a field, for a select: the most common first (the server stacks at most 100). */
function useStackOptions(incidentId, field, refresh) {
  const [options, setOptions] = useState(NO_OPTIONS)
  useEffect(() => {
    const controller = new AbortController()
    evidence
      .stack(incidentId, { field, order: 'common', limit: 100, filters: BASE, signal: controller.signal })
      .then((answer) => setOptions(answer.values.map((item) => String(item.value))))
      .catch(() => setOptions(NO_OPTIONS))
    return () => controller.abort()
  }, [incidentId, field, refresh])
  return options
}

/**
 * @param {{ incident: object, sources: object[], canWrite: boolean, refresh: number, matter: boolean,
 *   onMatterChange: (on: boolean) => void }} props
 * `sources`: the event-log sources, to say which file a record came from; `refresh` changes when
 * files were added or read, so the table and the lists of values load again. `matter` keeps to the events
 * that matter (the page owns it: the count of its tab follows it).
 */
export default function EventsSection({ incident, sources, canWrite, refresh, matter, onMatterChange }) {
  const { askText } = useContextMenu()
  const { showToast } = useToast()
  const menu = useItemMenu(incident)
  const [filters, setFilters] = useState(() => incidentRange(incident))
  const [rows, setRows] = useState([])
  const [flags, setFlags] = useState({}) // key -> flagged, what was marked here since the page loaded
  const [notes, setNotes] = useState({}) // key -> note
  const [viewing, setViewing] = useState(null)
  const [stacking, setStacking] = useState(null)
  const channels = useStackOptions(incident.id, 'channel', refresh)
  const hosts = useStackOptions(incident.id, 'host', refresh)

  // Another incident starts with its own range, not the last one's.
  useEffect(() => {
    setFilters(incidentRange(incident))
    setFlags({})
    setNotes({})
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only another incident resets the filters, not an edit of its window
  }, [incident.id])

  const scope = useMemo(() => (matter ? { ...BASE, matter: true } : BASE), [matter])
  const base = useMemo(() => evidence.recordsLoader(incident.id, scope, FIELDS), [incident.id, scope])
  const load = useCallback(
    async (args) => {
      const page = await base(args)
      setRows(page.items)
      return page
    },
    [base],
  )

  const mark = useCallback(
    async (row, { flagged = flaggedOf(row, flags), note = notes[row.key] ?? row.note } = {}) => {
      try {
        await evidence.putMark(incident.id, { key: row.key, flagged, note })
        setFlags((before) => ({ ...before, [row.key]: flagged }))
        setNotes((before) => ({ ...before, [row.key]: note }))
      } catch (failure) {
        showToast({ message: failure?.message || 'The mark could not be saved.' })
      }
    },
    [incident.id, flags, notes, showToast],
  )
  const addNote = async (row) => {
    const text = await askText({
      title: 'Note on this event',
      label: 'Note',
      placeholder: 'What this event shows',
      confirm: 'Save',
    })
    if (text !== null && text !== undefined) mark(row, { note: text.trim() })
  }

  const columns = useMemo(
    () => [
      {
        key: 'flag',
        label: '',
        className: 'w-px',
        render: (row) => {
          const flagged = flaggedOf(row, flags)
          const note = notes[row.key] ?? row.note
          return (
            <span className="inline-flex items-center gap-1">
              <button
                type="button"
                disabled={!canWrite}
                onClick={(event) => {
                  event.stopPropagation()
                  mark(row, { flagged: !flagged })
                }}
                aria-label={flagged ? 'Remove flag' : 'Flag as malicious'}
                aria-pressed={flagged}
                title={flagged ? 'Remove flag' : 'Flag as malicious'}
                className={[
                  'inline-flex items-center justify-center p-1 transition-colors disabled:cursor-not-allowed',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                  flagged ? 'text-accent hover:text-accent-fg' : 'text-fg-muted hover:text-accent',
                ].join(' ')}
              >
                <Flag className="h-4 w-4" fill={flagged ? 'currentColor' : 'none'} />
              </button>
              {note && <StickyNote className="h-3.5 w-3.5 text-fg-muted" aria-label={`Note: ${note}`} />}
            </span>
          )
        },
      },
      {
        key: 'ts',
        label: 'Time',
        order: 'time',
        render: (row) => (
          <span className="whitespace-nowrap font-mono text-xs text-fg">
            {Number.isFinite(row.ts) ? formatDateTime(row.ts) : '—'}
          </span>
        ),
      },
      {
        key: 'host',
        label: 'Host',
        filterKey: 'host',
        stackField: 'host',
        hideable: true,
        render: (row) => <span className="font-mono text-xs text-fg">{row.host || '—'}</span>,
      },
      {
        key: 'channel',
        label: 'Channel',
        filterKey: 'channel',
        stackField: 'channel',
        hideable: true,
        render: (row) => <span title={row.channel}>{getChannel(row.channel)?.short ?? (row.channel || '—')}</span>,
      },
      {
        key: 'eventId',
        label: 'Event ID',
        filterKey: 'eventId',
        stackField: 'eventId',
        render: (row) => (
          <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
            <span className="font-mono text-xs text-fg">{row.eventId ?? '—'}</span>
            <span className="text-xs text-fg-muted">{getEventDefinition(row.channel, row.eventId)?.label}</span>
          </span>
        ),
      },
      {
        key: 'level',
        label: 'Level',
        hideable: true,
        render: (row) => <span className="font-mono text-xs text-fg-muted">{levelText(row.data?.level) || '—'}</span>,
      },
      {
        key: 'username',
        label: 'User',
        filterKey: 'username',
        stackField: 'username',
        hideable: true,
        render: (row) => <span className="whitespace-nowrap font-mono text-xs text-fg">{row.username || '—'}</span>,
      },
      {
        key: 'summary',
        label: 'Summary',
        render: (row) => (
          <span className="line-clamp-2 block max-w-xl break-all font-mono text-xs text-fg" title={row.summary}>
            {row.summary || '—'}
          </span>
        ),
      },
      {
        key: 'source',
        label: 'Source',
        className: 'w-px',
        render: (row) => (
          <Button
            variant="ghost"
            size="xs"
            icon={FileSearch}
            title="Open the original behind this event"
            onClick={(event) => {
              event.stopPropagation()
              setViewing(row)
            }}
          >
            Source
          </Button>
        ),
      },
    ],
    [flags, notes, canWrite, mark],
  )

  const setFilter = (name, value) => setFilters((before) => withFilter(before, name, value))
  const hasIncidentRange = incident.suspiciousStart != null || incident.suspiciousEnd != null
  const choices = (values, current, empty) => [
    { value: '', label: empty },
    ...(current && !values.includes(current) ? [{ value: current, label: current }] : []),
    ...values.map((value) => ({ value, label: getChannel(value)?.short ?? value })),
  ]

  const toolbar = (
    <div className="flex flex-wrap items-center gap-2">
      <Select
        value={filters.channel ?? ''}
        onChange={(value) => setFilter('channel', value)}
        options={choices(channels, filters.channel, 'All channels')}
        label="Channel"
      />
      <FilterInput
        label="Event ID"
        value={String(filters.eventId ?? '')}
        inputMode="numeric"
        width="w-20"
        onCommit={(value) => setFilter('eventId', /^\d+$/.test(value) ? value : '')}
      />
      <Select
        value={filters.host ?? ''}
        onChange={(value) => setFilter('host', value)}
        options={choices(hosts, filters.host, 'All hosts')}
        label="Host"
      />
      <FilterInput label="User" value={filters.username ?? ''} onCommit={(value) => setFilter('username', value)} />
      <DateTimeRangeFilter
        start={filters.from ?? null}
        end={filters.to ?? null}
        onChange={({ start, end }) => setFilters((before) => withFilter(withFilter(before, 'from', start), 'to', end))}
      />
      <Button
        variant="ghost"
        size="xs"
        icon={CalendarClock}
        disabled={!hasIncidentRange}
        title="Set the range to the incident's suspicious activity window"
        onClick={() => setFilters((before) => ({ ...before, ...incidentRange(incident) }))}
      >
        Use incident range
      </Button>
      <button
        type="button"
        aria-pressed={matter}
        title={
          matter
            ? 'Showing the events that matter: click to see all events'
            : 'Showing all events: click to see only the events that matter'
        }
        onClick={() => onMatterChange(!matter)}
        className={`inline-flex items-center gap-1.5 border px-2.5 py-1.5 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${matter ? 'border-accent-strong bg-accent-soft text-accent-fg' : 'border-line text-fg-muted hover:text-fg'}`}
      >
        <Star className="h-3.5 w-3.5" aria-hidden="true" />
        Events that matter
      </button>
      {matter && (
        <Button variant="ghost" size="xs" onClick={() => onMatterChange(false)}>
          Show all events
        </Button>
      )}
      <button
        type="button"
        aria-pressed={Boolean(filters.flagged)}
        onClick={() => setFilter('flagged', !filters.flagged)}
        className={`inline-flex items-center gap-1.5 border px-2.5 py-1.5 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${filters.flagged ? 'border-accent-strong bg-accent-soft text-accent-fg' : 'border-line text-fg-muted hover:text-fg'}`}
      >
        <Flag className="h-3.5 w-3.5" aria-hidden="true" />
        Flagged only
      </button>
    </div>
  )

  const rowMenu = (event, row, filterItems) =>
    menu(event, {
      title: `${row.eventId ?? ''} ${row.summary ?? ''}`.trim().slice(0, 80) || 'Event',
      actions: [
        ...filterItems,
        canWrite && {
          label: flaggedOf(row, flags) ? 'Remove flag' : 'Flag as malicious',
          icon: Flag,
          onSelect: () => mark(row, { flagged: !flaggedOf(row, flags) }),
        },
        canWrite && { label: 'Add a note…', icon: StickyNote, onSelect: () => addNote(row) },
        { label: 'Open the source', icon: FileSearch, onSelect: () => setViewing(row) },
      ].filter(Boolean),
      copy: [
        { label: 'summary', text: row.summary },
        { label: 'user', text: row.username },
        { label: 'host', text: row.host },
      ].filter((item) => item.text),
      record: {
        time: row.ts,
        eventId: row.eventId,
        channel: row.channel,
        host: row.host,
        user: row.username,
        summary: row.summary,
      },
    })

  const near = viewing ? neighbourRecords(rows, viewing.id) : null

  return (
    <div role="tabpanel" aria-labelledby="tab-eventlogs-events">
      <ServerTable
        tableKey="eventlogs"
        load={load}
        columns={columns}
        filters={filters}
        onFiltersChange={setFilters}
        toolbar={toolbar}
        refreshKey={`${refresh}:${matter}`}
        defaultOrder="-time"
        searchPlaceholder="Search the summaries…"
        emptyMessage={
          matter
            ? 'No events that matter match the current filters: show all events to see the rest'
            : 'No events match the current filters'
        }
        rowClassName={(row) => `cursor-pointer ${flaggedOf(row, flags) ? FLAG_HIGHLIGHT : ''}`}
        onRowClick={setViewing}
        onRowContextMenu={rowMenu}
        onStack={setStacking}
      />
      {stacking && (
        <StackPanel
          incidentId={incident.id}
          field={stacking}
          label={columns.find((column) => column.stackField === stacking)?.label}
          filters={{ ...filters, ...scope }}
          onClose={() => setStacking(null)}
          onPick={(value) => {
            // The stack fields of the columns are the names of their filters.
            setFilter(stacking, String(value))
            setStacking(null)
          }}
        />
      )}
      {viewing && (
        <SourceViewer
          incidentId={incident.id}
          source={sourceOfRecord(viewing, sources) ?? { id: viewing.sourceId, fileName: '' }}
          record={{ id: viewing.id }}
          onClose={() => setViewing(null)}
          onPrev={near.previous ? () => setViewing(near.previous) : null}
          onNext={near.next ? () => setViewing(near.next) : null}
        />
      )}
    </div>
  )
}
