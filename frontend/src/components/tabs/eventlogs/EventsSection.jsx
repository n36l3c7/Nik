/*
 * Event-log events as a flaggable, searchable table with the same SOC
 * treatment as the other tabs (keyword + ruleset badges, business-hours
 * anomaly, row flag, suspicious-window range filter), plus channel and
 * category filters. Clicking a row opens every stored field of the event.
 */
import { Fragment, useEffect, useMemo, useState } from 'react'
import { CalendarClock, Clock, Flag, RotateCcw, ScrollText } from 'lucide-react'
import { Badge, Button, Card, DataTable, Modal, Select } from '../../ui/index.js'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { useRowMenu } from '../../menu/useRowMenu.js'
import { IocValue } from '../../../context/IocLookupContext.jsx'
import { EVENT_CATEGORIES } from '../../../config/eventLogs.js'
import { guessIocType } from '../../../domain/iocs.js'
import { formatDateTime } from '../../../lib/time.js'
import DateTimeRangeFilter from '../browser/DateTimeRangeFilter.jsx'

const NIGHT_TOOLTIP = 'Outside configured business hours'

const DETECTION_FILTER_OPTIONS = [
  { value: 'all', label: 'All' },
  { value: 'flagged', label: 'Only flagged by SOC' },
  { value: 'high', label: 'High severity' },
  { value: 'outside', label: 'Outside hours' },
]

const CATEGORY_OPTIONS = [
  { value: 'all', label: 'All categories' },
  ...Object.entries(EVENT_CATEGORIES).map(([value, { label }]) => ({ value, label })),
]

const ROW_SEVERITY_CLASSES = {
  high: 'bg-high-soft border-l-2 border-l-high-line',
  medium: 'bg-med-soft border-l-2 border-l-med-line',
}
const FLAG_HIGHLIGHT = 'bg-accent-soft border-l-2 border-l-accent-strong'
const NO_FLAGS = {}

/** The payload toggleFlag() stores for an event-log row (also used by the timeline). */
export function eventLogFlaggable(event) {
  return {
    key: event.id,
    browserId: event.channelLabel,
    section: 'eventlogs',
    eventType: 'eventlog',
    title: event.title,
    url: '',
    time: event.time,
  }
}

function DetectionCell({ event }) {
  const { keywordMatches, isAnomalousTime } = event.soc
  if (keywordMatches.length === 0 && !isAnomalousTime && !event.recovered) {
    return <span className="text-fg-muted">—</span>
  }
  return (
    <div className="flex flex-wrap items-center gap-1">
      {keywordMatches.map((rule) => (
        <Badge key={rule.id} color={rule.severity === 'high' ? 'red' : 'amber'} title={rule.description}>
          {rule.label}
        </Badge>
      ))}
      {isAnomalousTime && (
        <Badge color="amber" title={NIGHT_TOOLTIP}>
          outside hours
        </Badge>
      )}
      {event.recovered && (
        <Badge color="violet" title="Recovered from the unused space of the .evtx file (for example after a clear)">
          recovered
        </Badge>
      )}
    </div>
  )
}

function Details({ event }) {
  const entries = Object.entries(event.data ?? {})
  return (
    <dl className="grid grid-cols-[minmax(8rem,14rem)_minmax(0,1fr)] gap-x-3 gap-y-0.5 font-mono text-[11px]">
      {[
        ['Channel', event.channel],
        ['Provider', event.provider],
        ['Computer', event.computer],
        ['Record', event.recordId],
      ]
        .filter(([, value]) => value != null && value !== '')
        .map(([key, value]) => (
          <Fragment key={key}>
            <dt className="text-fg-subtle">{key}</dt>
            <dd className="break-all text-fg-muted">{value}</dd>
          </Fragment>
        ))}
      {entries.map(([key, value]) => (
        <Fragment key={key}>
          <dt className="text-fg-subtle">{key}</dt>
          <dd className="whitespace-pre-wrap break-all text-fg">
            {guessIocType(value) ? <IocValue type={guessIocType(value)} value={value} /> : value}
          </dd>
        </Fragment>
      ))}
    </dl>
  )
}

/**
 * @param {{ incident: object, events: Array, channelOptions: Array<{value, label}> }} props
 */
export default function EventsSection({ incident, events, channelOptions }) {
  const { toggleFlag } = useIncidents()
  const rowMenu = useRowMenu(incident)
  const flags = incident?.flags ?? NO_FLAGS
  const [detectionFilter, setDetectionFilter] = useState('all')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const [channelFilter, setChannelFilter] = useState('all')
  const [range, setRange] = useState(() => ({
    start: incident?.suspiciousStart ?? null,
    end: incident?.suspiciousEnd ?? null,
  }))
  const [expanded, setExpanded] = useState(null)
  const [resetToken, setResetToken] = useState(0)

  useEffect(() => {
    setRange({ start: incident?.suspiciousStart ?? null, end: incident?.suspiciousEnd ?? null })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incident?.id])

  const filtered = useMemo(
    () =>
      events.filter((event) => {
        if (detectionFilter === 'flagged' && !event.soc.isFlagged) return false
        if (detectionFilter === 'high' && event.soc.severity !== 'high') return false
        if (detectionFilter === 'outside' && !event.soc.isAnomalousTime) return false
        if (categoryFilter !== 'all' && event.category !== categoryFilter) return false
        if (channelFilter !== 'all' && event.channel !== channelFilter) return false
        if (range.start != null && (event.time == null || event.time < range.start)) return false
        if (range.end != null && (event.time == null || event.time > range.end)) return false
        return true
      }),
    [events, detectionFilter, categoryFilter, channelFilter, range],
  )

  const columns = useMemo(
    () => [
      {
        key: 'flag',
        label: '',
        className: 'w-px',
        render: (row) => {
          const flagged = Boolean(flags[row.id])
          return (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation()
                toggleFlag(incident.id, eventLogFlaggable(row))
              }}
              aria-label={flagged ? 'Remove flag' : 'Flag as malicious'}
              title={flagged ? 'Remove flag' : 'Flag as malicious'}
              className={[
                'inline-flex items-center justify-center p-1 transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                flagged ? 'text-accent hover:text-accent-fg' : 'text-fg-muted hover:text-accent',
              ].join(' ')}
            >
              <Flag className="h-4 w-4" fill={flagged ? 'currentColor' : 'none'} />
            </button>
          )
        },
      },
      {
        key: 'time',
        label: 'Date/Time',
        sortable: true,
        sortAccessor: (row) => row.time ?? 0,
        render: (row) => (
          <span className="inline-flex items-center gap-1.5 whitespace-nowrap font-mono text-xs text-fg">
            {Number.isFinite(row.time) ? formatDateTime(row.time) : '—'}
            {row.soc.isAnomalousTime && <Clock className="h-3.5 w-3.5 text-med" aria-label={NIGHT_TOOLTIP} />}
          </span>
        ),
      },
      {
        key: 'channelLabel',
        label: 'Channel',
        sortable: true,
        render: (row) => <Badge color="slate">{row.channelLabel}</Badge>,
      },
      {
        key: 'eventId',
        label: 'Event',
        sortable: true,
        sortAccessor: (row) => row.eventId,
        render: (row) => (
          <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-sm text-fg">
            <span className="font-mono text-xs text-fg-muted">{row.eventId}</span>
            {row.label}
          </span>
        ),
      },
      {
        key: 'summary',
        label: 'Details',
        render: (row) => (
          <span className="line-clamp-2 block max-w-xl break-all font-mono text-xs text-fg" title={row.summary}>
            {row.summary || '—'}
          </span>
        ),
      },
      {
        key: 'user',
        label: 'User',
        sortable: true,
        render: (row) =>
          row.user ? (
            <span className="whitespace-nowrap font-mono text-xs text-fg">{row.user}</span>
          ) : (
            <span className="text-fg-muted">—</span>
          ),
      },
      {
        key: 'category',
        label: 'Category',
        sortable: true,
        render: (row) => <Badge color={EVENT_CATEGORIES[row.category]?.color ?? 'slate'}>{row.categoryLabel}</Badge>,
      },
      { key: 'detection', label: 'Detection', render: (row) => <DetectionCell event={row} /> },
    ],
    [flags, incident.id, toggleFlag],
  )

  const expandedEvent = expanded ? events.find((e) => e.id === expanded) : null
  const hasIncidentRange = incident?.suspiciousStart != null || incident?.suspiciousEnd != null

  const toolbar = (
    <div className="flex flex-wrap items-center gap-2">
      <Select value={detectionFilter} onChange={setDetectionFilter} options={DETECTION_FILTER_OPTIONS} />
      <Select value={categoryFilter} onChange={setCategoryFilter} options={CATEGORY_OPTIONS} />
      <Select
        value={channelFilter}
        onChange={setChannelFilter}
        options={[{ value: 'all', label: 'All channels' }, ...channelOptions]}
      />
      <DateTimeRangeFilter start={range.start} end={range.end} onChange={setRange} />
      <Button
        variant="ghost"
        size="xs"
        icon={CalendarClock}
        onClick={() => setRange({ start: incident?.suspiciousStart ?? null, end: incident?.suspiciousEnd ?? null })}
        disabled={!hasIncidentRange}
        title="Set the range to the incident's suspicious activity window"
      >
        Use incident range
      </Button>
      <Button
        variant="ghost"
        size="xs"
        icon={RotateCcw}
        onClick={() => {
          setDetectionFilter('all')
          setCategoryFilter('all')
          setChannelFilter('all')
          setRange({ start: null, end: null })
          setResetToken((t) => t + 1)
        }}
      >
        Reset filters
      </Button>
    </div>
  )

  return (
    <Card title="Events" icon={ScrollText}>
      <DataTable
        key={resetToken}
        columns={columns}
        data={filtered}
        searchKeys={['_search']}
        searchPlaceholder="Search events, users, fields…"
        defaultSort={{ key: 'time', dir: 'desc' }}
        rowClassName={(row) =>
          `cursor-pointer ${flags[row.id] ? FLAG_HIGHLIGHT : (ROW_SEVERITY_CLASSES[row.soc.severity] ?? '')}`
        }
        onRowClick={(row) => setExpanded(row.id)}
        onRowContextMenu={(event, row) =>
          rowMenu(event, {
            flaggable: eventLogFlaggable(row),
            record: {
              time: row.time,
              eventId: row.eventId,
              channel: row.channel,
              computer: row.computer,
              data: row.data,
            },
          })
        }
        toolbar={toolbar}
        emptyMessage="No events match the current filters"
      />
      <Modal
        open={Boolean(expandedEvent)}
        onClose={() => setExpanded(null)}
        title={expandedEvent ? `${expandedEvent.eventId} ${expandedEvent.label}` : ''}
        maxWidth="max-w-3xl"
      >
        {expandedEvent && (
          <div className="space-y-3">
            <p className="font-mono text-xs text-fg-muted">
              {formatDateTime(expandedEvent.time)} · {expandedEvent.channelLabel}
            </p>
            <DetectionCell event={expandedEvent} />
            <Details event={expandedEvent} />
          </div>
        )}
      </Modal>
    </Card>
  )
}
