/*
 * Generic endpoint-artifact section: renders one category's records as a
 * flaggable, searchable table with the same SOC treatment as browser and
 * command events (keyword detection, business-hours anomaly, per-row flag,
 * suspicious-window range filter). Columns are driven by the category config,
 * so all four categories share this one component.
 */
import { useEffect, useMemo, useState } from 'react'
import {
  CalendarClock,
  Check,
  Clock,
  Copy,
  Flag,
  RotateCcw,
  TriangleAlert,
} from 'lucide-react'
import { Badge, Button, Card, DataTable, EmptyState, Select, StatCard } from '../../ui/index.js'
import { useSocEngine } from '../../../context/SettingsContext.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { computeSocStats } from '../../../utils/soc.js'
import { buildArtifactEvents } from '../../../utils/artifacts.js'
import { formatDateTime } from '../../../utils/time.js'
import DateTimeRangeFilter from '../browser/DateTimeRangeFilter.jsx'

const NIGHT_TOOLTIP = 'Outside configured business hours'

const DETECTION_FILTER_OPTIONS = [
  { value: 'all', label: 'All' },
  { value: 'flagged', label: 'Only flagged by SOC' },
  { value: 'high', label: 'High severity' },
  { value: 'outside', label: 'Outside hours' },
]

const ROW_SEVERITY_CLASSES = {
  high: 'bg-red-500/5 dark:bg-red-500/10 border-l-2 border-l-red-500',
  medium: 'bg-amber-500/5 dark:bg-amber-500/10 border-l-2 border-l-amber-500',
}
const FLAG_HIGHLIGHT = 'bg-cyan-500/5 dark:bg-cyan-500/10 border-l-2 border-l-cyan-500'

function TimeCell({ event }) {
  if (!Number.isFinite(event.time)) {
    return <span className="font-mono text-xs text-slate-400 dark:text-slate-500">—</span>
  }
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap font-mono text-xs text-slate-700 dark:text-slate-300">
      {formatDateTime(event.time)}
      {event.soc.isAnomalousTime && (
        <span title={NIGHT_TOOLTIP} className="inline-flex shrink-0">
          <Clock className="h-3.5 w-3.5 text-amber-500" aria-label={NIGHT_TOOLTIP} />
        </span>
      )}
    </span>
  )
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  if (!text) return null
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    } catch {
      /* insecure context: ignore */
    }
  }
  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label="Copy"
      title="Copy"
      className="shrink-0 rounded p-0.5 text-slate-400 opacity-0 transition hover:text-cyan-600 focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 group-hover:opacity-100 dark:text-slate-500 dark:hover:text-cyan-400"
    >
      {copied ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
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
        'inline-flex items-center justify-center rounded p-1 transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500',
        flagged
          ? 'text-cyan-600 hover:text-cyan-500 dark:text-cyan-400'
          : 'text-slate-400 hover:text-cyan-600 dark:text-slate-500 dark:hover:text-cyan-400',
      ].join(' ')}
    >
      <Flag className="h-4 w-4" fill={flagged ? 'currentColor' : 'none'} />
    </button>
  )
}

function DetectionCell({ event }) {
  const { keywordMatches, isAnomalousTime } = event.soc
  if (keywordMatches.length === 0 && !isAnomalousTime) {
    return <span className="text-slate-400 dark:text-slate-500">—</span>
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

/** A category field cell (monospace when the column asks for it). */
function FieldCell({ event, column }) {
  const value = event.fields?.[column.key] ?? ''
  if (!value) return <span className="text-slate-400 dark:text-slate-500">—</span>
  const base = column.mono
    ? 'font-mono text-xs text-slate-700 dark:text-slate-300'
    : 'text-sm text-slate-700 dark:text-slate-200'
  const cell = (
    <span className={`${column.grow ? 'break-all' : 'whitespace-nowrap'} ${base}`} title={value}>
      {value}
    </span>
  )
  // The primary/grow monospace columns get a hover copy button.
  if (column.mono && column.grow) {
    return (
      <span className="group inline-flex min-w-0 items-center gap-1.5">
        {cell}
        <CopyButton text={value} />
      </span>
    )
  }
  return cell
}

/**
 * @param {{ incident: object, category: object, records?: Array }} props
 */
export default function ArtifactSection({ incident, category, records = [] }) {
  const engine = useSocEngine()
  const { toggleFlag } = useIncidents()
  const flags = incident?.flags ?? {}

  const [detectionFilter, setDetectionFilter] = useState('all')
  const [range, setRange] = useState(() => ({
    start: incident?.suspiciousStart ?? null,
    end: incident?.suspiciousEnd ?? null,
  }))
  const [resetToken, setResetToken] = useState(0)

  useEffect(() => {
    setRange({ start: incident?.suspiciousStart ?? null, end: incident?.suspiciousEnd ?? null })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incident?.id, category.id])

  const events = useMemo(
    () => buildArtifactEvents({ records, category, engine }),
    [records, category, engine],
  )

  const stats = useMemo(() => computeSocStats(events), [events])
  const withTime = useMemo(() => events.filter((e) => Number.isFinite(e.time)).length, [events])
  const flaggedCount = useMemo(
    () => events.reduce((acc, e) => acc + (flags[e.id] ? 1 : 0), 0),
    [events, flags],
  )

  const filtered = useMemo(
    () =>
      events.filter((event) => {
        if (detectionFilter === 'flagged' && !event.soc.isFlagged) return false
        if (detectionFilter === 'high' && event.soc.severity !== 'high') return false
        if (detectionFilter === 'outside' && !event.soc.isAnomalousTime) return false
        if (range.start != null && (event.time == null || event.time < range.start)) return false
        if (range.end != null && (event.time == null || event.time > range.end)) return false
        return true
      }),
    [events, detectionFilter, range],
  )

  const columns = useMemo(
    () => buildColumns({ category, incidentId: incident?.id, flags, toggleFlag }),
    [category, incident?.id, flags, toggleFlag],
  )

  // DataTable searches top-level keys only; buildArtifactEvents flattens the
  // record fields into `_search` for exactly this.
  const searchKeys = ['_search']

  const hasIncidentRange = incident?.suspiciousStart != null || incident?.suspiciousEnd != null
  const useIncidentRange = () =>
    setRange({ start: incident?.suspiciousStart ?? null, end: incident?.suspiciousEnd ?? null })
  const resetFilters = () => {
    setDetectionFilter('all')
    setRange({ start: null, end: null })
    setResetToken((t) => t + 1)
  }

  if (records.length === 0) {
    return (
      <EmptyState
        icon={category.icon}
        title={`No ${category.label.toLowerCase()} yet`}
        message="Import a CSV/JSON export from the 'Data source' card above, or use 'Load demo data' to explore the platform."
      />
    )
  }

  const toolbar = (
    <div className="flex flex-wrap items-center gap-2">
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

  const CategoryIcon = category.icon

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={CategoryIcon} label={`Total ${category.label.toLowerCase()}`} value={stats.total} />
        <StatCard icon={Clock} label="With timestamp" value={withTime} />
        <StatCard
          icon={TriangleAlert}
          label="SOC detections"
          value={stats.flagged}
          tone={stats.flagged > 0 ? 'accent' : 'default'}
          hint={stats.high > 0 ? `${stats.high} high-severity` : undefined}
        />
        <StatCard
          icon={Flag}
          label="Flagged"
          value={flaggedCount}
          tone={flaggedCount > 0 ? 'accent' : 'default'}
        />
      </div>

      <Card title={category.label} icon={CategoryIcon}>
        <DataTable
          key={resetToken}
          columns={columns}
          data={filtered}
          searchKeys={searchKeys}
          searchPlaceholder={`Search ${category.label.toLowerCase()}…`}
          defaultSort={{ key: 'time', dir: 'desc' }}
          rowClassName={(row) =>
            flags[row.id] ? FLAG_HIGHLIGHT : (ROW_SEVERITY_CLASSES[row.soc.severity] ?? '')
          }
          toolbar={toolbar}
          emptyMessage="No records match the current filters"
        />
      </Card>
    </div>
  )
}

function buildColumns({ category, incidentId, flags, toggleFlag }) {
  const flagColumn = {
    key: 'flag',
    label: '',
    className: 'w-px',
    render: (row) => (
      <FlagButton
        flagged={Boolean(flags[row.id])}
        onToggle={() =>
          toggleFlag(incidentId, {
            key: row.id,
            browserId: category.id, // reuse the flag "source" field for the category
            section: `endpoint:${category.id}`,
            eventType: category.id,
            title: row.fields?.[category.primaryField] || '',
            url: '',
            time: row.time,
          })
        }
      />
    ),
  }

  const timeColumn = {
    key: 'time',
    label: 'Date/Time',
    sortable: true,
    sortAccessor: (row) => row.time ?? 0,
    render: (row) => <TimeCell event={row} />,
  }

  const sourceColumn = {
    key: 'sourceName',
    label: 'Source',
    sortable: true,
    sortAccessor: (row) => row.sourceName ?? '',
    render: (row) =>
      row.sourceName ? (
        <Badge color="slate">{row.sourceName}</Badge>
      ) : (
        <span className="text-slate-400 dark:text-slate-500">—</span>
      ),
  }

  const fieldColumns = category.columns.map((column) => ({
    key: column.key,
    label: column.label,
    align: column.align,
    sortable: true,
    sortAccessor: (row) => (row.fields?.[column.key] ?? '').toLowerCase?.() ?? '',
    render: (row) => <FieldCell event={row} column={column} />,
  }))

  const detectionColumn = {
    key: 'detection',
    label: 'Detection',
    render: (row) => <DetectionCell event={row} />,
  }

  return [flagColumn, timeColumn, sourceColumn, ...fieldColumns, detectionColumn]
}
