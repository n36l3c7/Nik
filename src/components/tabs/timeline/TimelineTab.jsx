import { useEffect, useMemo, useState } from 'react'
import { Activity, CalendarClock, Clock, Flag, ListTree, RotateCcw, TriangleAlert } from 'lucide-react'
import { Badge, Button, Card, DataTable, EmptyState, Select, StatCard } from '../../ui/index.js'
import { useSocEngine } from '../../../context/SettingsContext.jsx'
import { useNavigation } from '../../../context/NavigationContext.jsx'
import { useRowMenu } from '../../menu/useRowMenu.js'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { computeSocStats } from '../../../utils/soc.js'
import { buildTimelineEvents, TIMELINE_SOURCE_META } from '../../../utils/timeline.js'
import { getArtifactCategoryById } from '../../../config/artifacts.js'
import { formatDateTime } from '../../../utils/time.js'
import EventTypeIcon from '../browser/EventTypeIcon.jsx'
import DateTimeRangeFilter from '../browser/DateTimeRangeFilter.jsx'
import { truncate } from '../../../utils/url.js'

/*
 * "Timeline" tab: the super-timeline. Merges every timestamped event across the
 * incident (browser history/downloads, shell commands, endpoint artifacts) into
 * one chronological table. Entries without a timestamp are excluded by
 * buildTimelineEvents. Rows can be flagged straight from here and carry the
 * same SOC highlighting as their source tabs.
 */

const NIGHT_TOOLTIP = 'Outside configured business hours'

const DETECTION_FILTER_OPTIONS = [
  { value: 'all', label: 'All detections' },
  { value: 'flagged', label: 'Only flagged by SOC' },
  { value: 'high', label: 'High severity' },
  { value: 'outside', label: 'Outside hours' },
]

const SOURCE_FILTER_OPTIONS = [
  { value: 'all', label: 'All sources' },
  { value: 'browser', label: 'Browser' },
  { value: 'command', label: 'Commands' },
  { value: 'endpoint', label: 'Endpoint' },
  { value: 'eventlog', label: 'Event logs' },
  { value: 'sample', label: 'Samples' },
  { value: 'mail', label: 'E-mails' },
]

const ROW_SEVERITY_CLASSES = {
  high: 'bg-high-soft border-l-2 border-l-high-line',
  medium: 'bg-med-soft border-l-2 border-l-med-line',
}
const FLAG_HIGHLIGHT = 'bg-accent-soft border-l-2 border-l-accent-strong'

function TimeCell({ event }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap font-mono text-xs text-fg">
      {formatDateTime(event.time)}
      {event.soc.isAnomalousTime && (
        <span title={NIGHT_TOOLTIP} className="inline-flex shrink-0">
          <Clock className="h-3.5 w-3.5 text-med" aria-label={NIGHT_TOOLTIP} />
        </span>
      )}
    </span>
  )
}

function FlagButton({ flagged, onToggle }) {
  return (
    <button
      type="button"
      onClick={onToggle}
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
}

// Stable fallback, so memoized computations do not rerun on every render.
const NO_FLAGS = {}

/** Source badge + a per-type icon (browser/command types reuse EventTypeIcon). */
function SourceCell({ event }) {
  const meta = TIMELINE_SOURCE_META[event.sourceType] ?? TIMELINE_SOURCE_META.browser
  const category = event.sourceType === 'endpoint' ? getArtifactCategoryById(event.eventType) : null
  const CatIcon = category?.icon
  return (
    <div className="flex items-center gap-2">
      <Badge color={meta.color}>{event.sourceLabel}</Badge>
      {event.sourceType === 'endpoint' ? (
        CatIcon && <CatIcon className={`h-3.5 w-3.5 ${category.accent}`} aria-hidden="true" />
      ) : (
        <EventTypeIcon type={event.eventType} />
      )}
    </div>
  )
}

function DetectionCell({ event }) {
  const { keywordMatches, isAnomalousTime } = event.soc
  if (keywordMatches.length === 0 && !isAnomalousTime) {
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
    </div>
  )
}

export default function TimelineTab({ incident }) {
  const engine = useSocEngine()
  const { toggleFlag } = useIncidents()
  const rowMenu = useRowMenu(incident, { timeline: false })
  const { requests, take } = useNavigation()
  const flags = incident?.flags ?? NO_FLAGS
  // "Show in the Timeline" from another tab: search for that event.
  const [initialQuery, setInitialQuery] = useState('')

  const [detectionFilter, setDetectionFilter] = useState('all')
  const [sourceFilter, setSourceFilter] = useState('all')
  const [range, setRange] = useState(() => ({
    start: incident?.suspiciousStart ?? null,
    end: incident?.suspiciousEnd ?? null,
  }))
  const [resetToken, setResetToken] = useState(0)

  useEffect(() => {
    setRange({ start: incident?.suspiciousStart ?? null, end: incident?.suspiciousEnd ?? null })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incident?.id])

  useEffect(() => {
    if (!requests.timeline) return
    const request = take('timeline')
    if (request?.search == null) return
    setDetectionFilter('all')
    setSourceFilter('all')
    setRange({ start: null, end: null })
    setInitialQuery(request.search)
    setResetToken((t) => t + 1)
  }, [requests.timeline, take])

  const data = incident?.data
  const events = useMemo(() => buildTimelineEvents(data, engine), [data, engine])

  const stats = useMemo(() => computeSocStats(events), [events])
  const flaggedCount = useMemo(() => events.reduce((acc, e) => acc + (flags[e.id] ? 1 : 0), 0), [events, flags])
  const spanLabel = useMemo(() => {
    if (events.length === 0) return '—'
    const first = events[events.length - 1].time
    const last = events[0].time
    const days = Math.max(1, Math.round((last - first) / 86_400_000))
    return `${days} day${days === 1 ? '' : 's'}`
  }, [events])

  const filtered = useMemo(
    () =>
      events.filter((event) => {
        if (sourceFilter !== 'all' && event.sourceType !== sourceFilter) return false
        if (detectionFilter === 'flagged' && !event.soc.isFlagged) return false
        if (detectionFilter === 'high' && event.soc.severity !== 'high') return false
        if (detectionFilter === 'outside' && !event.soc.isAnomalousTime) return false
        if (range.start != null && event.time < range.start) return false
        if (range.end != null && event.time > range.end) return false
        return true
      }),
    [events, sourceFilter, detectionFilter, range],
  )

  const columns = useMemo(
    () => buildColumns({ incidentId: incident?.id, flags, toggleFlag }),
    [incident?.id, flags, toggleFlag],
  )

  const hasIncidentRange = incident?.suspiciousStart != null || incident?.suspiciousEnd != null
  const useIncidentRange = () =>
    setRange({ start: incident?.suspiciousStart ?? null, end: incident?.suspiciousEnd ?? null })
  const resetFilters = () => {
    setDetectionFilter('all')
    setSourceFilter('all')
    setRange({ start: null, end: null })
    setInitialQuery('')
    setResetToken((t) => t + 1)
  }

  if (events.length === 0) {
    return (
      <div className="mx-auto max-w-3xl">
        <div className="border border-line bg-panel py-10">
          <EmptyState
            icon={ListTree}
            title="Nothing on the timeline yet"
            message="The timeline merges every timestamped event from the Browser, Command History and Endpoint Artifacts tabs. Import data (or load demo data) in those tabs and it shows up here in chronological order."
          />
        </div>
      </div>
    )
  }

  const toolbar = (
    <div className="flex flex-wrap items-center gap-2">
      <Select value={sourceFilter} onChange={setSourceFilter} options={SOURCE_FILTER_OPTIONS} />
      <Select value={detectionFilter} onChange={setDetectionFilter} options={DETECTION_FILTER_OPTIONS} />
      <DateTimeRangeFilter start={range.start} end={range.end} onChange={setRange} />
      <Button
        variant="ghost"
        size="xs"
        icon={CalendarClock}
        onClick={useIncidentRange}
        disabled={!hasIncidentRange}
        title="Set the range to the incident's suspicious activity window"
      >
        Use incident range
      </Button>
      <Button variant="ghost" size="xs" icon={RotateCcw} onClick={resetFilters}>
        Reset filters
      </Button>
    </div>
  )

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={Activity} label="Timeline events" value={stats.total} />
        <StatCard icon={Clock} label="Time span" value={spanLabel} />
        <StatCard
          icon={TriangleAlert}
          label="SOC detections"
          value={stats.flagged}
          tone={stats.flagged > 0 ? 'accent' : 'default'}
          hint={stats.high > 0 ? `${stats.high} high-severity` : undefined}
        />
        <StatCard icon={Flag} label="Flagged" value={flaggedCount} tone={flaggedCount > 0 ? 'accent' : 'default'} />
      </div>

      <Card title="Unified timeline" icon={ListTree}>
        <p className="mb-3 text-xs text-fg-muted">
          Every timestamped event across the incident, most recent first. Entries without a reliable timestamp (e.g.
          PSReadLine commands) are intentionally excluded.
        </p>
        <DataTable
          key={resetToken}
          columns={columns}
          data={filtered}
          searchKeys={['label', 'detail', 'sourceLabel']}
          searchPlaceholder="Search the timeline…"
          defaultSort={{ key: 'time', dir: 'desc' }}
          rowClassName={(row) => (flags[row.id] ? FLAG_HIGHLIGHT : (ROW_SEVERITY_CLASSES[row.soc.severity] ?? ''))}
          onRowContextMenu={(event, row) => rowMenu(event, { flaggable: row.flaggable, record: row })}
          initialQuery={initialQuery}
          toolbar={toolbar}
          emptyMessage="No events match the current filters"
        />
      </Card>
    </div>
  )
}

function buildColumns({ incidentId, flags, toggleFlag }) {
  return [
    {
      key: 'flag',
      label: '',
      className: 'w-px',
      render: (row) => (
        <FlagButton flagged={Boolean(flags[row.id])} onToggle={() => toggleFlag(incidentId, row.flaggable)} />
      ),
    },
    {
      key: 'time',
      label: 'Date/Time',
      sortable: true,
      sortAccessor: (row) => row.time ?? 0,
      render: (row) => <TimeCell event={row} />,
    },
    {
      key: 'source',
      label: 'Source',
      sortable: true,
      sortAccessor: (row) => row.sourceLabel,
      render: (row) => <SourceCell event={row} />,
    },
    {
      key: 'label',
      label: 'Event',
      render: (row) => (
        <div className="min-w-0">
          <p className="break-all text-sm text-fg">
            {truncate(row.label, 90) || <span className="italic text-fg-muted">(no label)</span>}
          </p>
          {row.detail && <p className="truncate font-mono text-xs text-fg-muted">{truncate(row.detail, 80)}</p>}
        </div>
      ),
    },
    {
      key: 'detection',
      label: 'Detection',
      render: (row) => <DetectionCell event={row} />,
    },
  ]
}
