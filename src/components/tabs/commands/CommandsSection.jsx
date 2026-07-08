/*
 * "Commands" section: the shell command history of the active shell, shown as
 * a flaggable, searchable table with the same SOC treatment as the browser
 * events (keyword detection, business-hours anomaly, per-row flag, date-time
 * range filter seeded from the incident's suspicious window).
 *
 * Analysts can FLAG any command as part of the malicious activity, narrow the
 * list with detection / time-range filters, and copy any command line to the
 * clipboard.
 */
import { useEffect, useMemo, useState } from 'react'
import {
  CalendarClock,
  Check,
  Clock,
  Copy,
  Flag,
  Hash,
  RotateCcw,
  Terminal,
  TriangleAlert,
} from 'lucide-react'
import { Badge, Button, Card, DataTable, EmptyState, Select, StatCard } from '../../ui/index.js'
import { useSocEngine } from '../../../context/SettingsContext.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { computeSocStats } from '../../../utils/soc.js'
import { buildCommandEvents } from '../../../utils/commands.js'
import { formatDateTime } from '../../../utils/time.js'
import DateTimeRangeFilter from '../browser/DateTimeRangeFilter.jsx'
import TopBinariesWidget from './TopBinariesWidget.jsx'

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

/* ---- Reusable cells (local copies keep this section self-contained) ------- */

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
      aria-label="Copy command"
      title="Copy command"
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

/* ---- Component ------------------------------------------------------------- */

/**
 * @param {{ incident: object, shellId: string, commands?: Array }} props
 */
export default function CommandsSection({ incident, shellId, commands = [] }) {
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
  }, [incident?.id])

  const events = useMemo(
    () => buildCommandEvents({ commands, engine }),
    [commands, engine],
  )

  const stats = useMemo(() => computeSocStats(events), [events])
  const withTime = useMemo(() => events.filter((e) => Number.isFinite(e.time)).length, [events])
  const flaggedCount = useMemo(
    () => events.reduce((acc, event) => acc + (flags[event.id] ? 1 : 0), 0),
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
    () => buildColumns({ incidentId: incident?.id, shellId, flags, toggleFlag }),
    [incident?.id, shellId, flags, toggleFlag],
  )

  const hasIncidentRange = incident?.suspiciousStart != null || incident?.suspiciousEnd != null
  const useIncidentRange = () =>
    setRange({ start: incident?.suspiciousStart ?? null, end: incident?.suspiciousEnd ?? null })
  const resetFilters = () => {
    setDetectionFilter('all')
    setRange({ start: null, end: null })
    setResetToken((token) => token + 1)
  }

  if (commands.length === 0) {
    return (
      <EmptyState
        icon={Terminal}
        title="No commands to show"
        message="Load the shell history from the 'Data source' card above, or use 'Load demo data' to explore the platform."
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

  return (
    <div className="space-y-4">
      {/* SOC stat-cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={Terminal} label="Total commands" value={stats.total} />
        <StatCard icon={Hash} label="With timestamp" value={withTime} />
        <StatCard
          icon={TriangleAlert}
          label="SOC detections"
          value={stats.flagged}
          tone={stats.flagged > 0 ? 'accent' : 'default'}
          hint={stats.high > 0 ? `${stats.high} high-severity` : undefined}
        />
        <StatCard
          icon={Flag}
          label="Flagged commands"
          value={flaggedCount}
          tone={flaggedCount > 0 ? 'accent' : 'default'}
        />
      </div>

      {/* Summary widget */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <TopBinariesWidget commands={commands} />
        <NoTimestampNote withTime={withTime} total={events.length} />
      </div>

      {/* Commands table */}
      <Card title="Command history" icon={Terminal}>
        <DataTable
          key={resetToken}
          columns={columns}
          data={filtered}
          searchKeys={['command']}
          searchPlaceholder="Search commands…"
          defaultSort={{ key: 'time', dir: 'desc' }}
          rowClassName={(row) =>
            flags[row.id] ? FLAG_HIGHLIGHT : (ROW_SEVERITY_CLASSES[row.soc.severity] ?? '')
          }
          toolbar={toolbar}
          emptyMessage="No commands match the current filters"
        />
      </Card>
    </div>
  )
}

/* ---- Local helpers -------------------------------------------------------- */

/** Small info card explaining when timestamps are (un)available. */
function NoTimestampNote({ withTime, total }) {
  const allMissing = total > 0 && withTime === 0
  return (
    <Card title="Timestamps" icon={Clock}>
      <p className="text-sm text-slate-600 dark:text-slate-300">
        {withTime.toLocaleString('en-US')} of {total.toLocaleString('en-US')} commands carry a
        timestamp.
      </p>
      <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
        {allMissing
          ? 'This history format stores no times. Sort order follows the file order; correlate with EDR / Event Logs (e.g. PowerShell 4104) to place commands on the timeline.'
          : 'Commands without a timestamp keep their original file order and sink to the bottom when sorting by time.'}
      </p>
    </Card>
  )
}

/* ---- Columns -------------------------------------------------------------- */

function buildColumns({ incidentId, shellId, flags, toggleFlag }) {
  return [
    {
      key: 'flag',
      label: '',
      className: 'w-px',
      render: (row) => (
        <FlagButton
          flagged={Boolean(flags[row.id])}
          onToggle={() =>
            toggleFlag(incidentId, {
              key: row.id,
              browserId: shellId, // reuse the flag "source" field for the shell id
              section: 'commands',
              eventType: 'command',
              title: row.command,
              url: '',
              time: row.time,
            })
          }
        />
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
      key: 'command',
      label: 'Command',
      render: (row) => (
        <div className="group flex items-start gap-1.5">
          <Terminal className="mt-0.5 h-3.5 w-3.5 shrink-0 text-violet-500 dark:text-violet-400" />
          <code className="min-w-0 flex-1 whitespace-pre-wrap break-all font-mono text-xs text-slate-800 dark:text-slate-100">
            {row.command}
          </code>
          <CopyButton text={row.command} />
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
