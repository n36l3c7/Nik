import { useCallback, useEffect, useMemo, useState } from 'react'
import { Activity, CalendarClock, Clock, ExternalLink, Flag, ListTree, RotateCcw, ShieldAlert } from 'lucide-react'
import { Badge, Button, Card, DataTable, EmptyState, Select, ServerTable, StatCard } from '../../ui/index.js'
import { GapControls, GapList } from './GapsBursts.jsx'
import { useSocEngine } from '../../../context/SettingsContext.jsx'
import { useNavigation } from '../../../context/NavigationContext.jsx'
import { useRowMenu } from '../../menu/useRowMenu.js'
import { LevelFilter, detectionsColumn } from '../../evidence/DetectionControls.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { detectionTone, levelsText, summedByLevel, totalOf } from '../../../domain/detections.js'
import { ARCHIVED_RECORDS_NOTE } from '../../../domain/archive.js'
import { burstBars, durationText, gapBands, onGrid } from '../../../domain/gapsBursts.js'
import { hostCounts } from '../../../domain/evidence.js'
import {
  HOST_KIND_META,
  KINDS_OFF_BY_DEFAULT,
  TIMELINE_SOURCE_META,
  buildTimelineEvents,
  density,
  fromLocalInput,
  recordLabel,
  toLocalInput,
} from '../../../domain/timeline.js'
import { formatDateTime } from '../../../lib/time.js'
import { truncate } from '../../../lib/url.js'
import { useCanWrite } from '../../../lib/useCanWrite.js'
import { useGapThresholds } from '../../../lib/useGapThresholds.js'
import { useEvidenceSummary } from '../../../lib/useEvidenceSummary.js'
import { evidence } from '../../../services/api.js'

/*
 * "Timeline" tab: the events of the incident in time.
 *
 *   - the density strip: how many events fall in each slice of time, host records (from the server,
 *     `evidence.histogram`) and the events of the document (mail, samples, captures, addresses) added to it;
 *   - the host records (browser, commands, endpoint, event logs), a page at a time from the server in order
 *     of time: nothing here ever holds more than a page of them;
 *   - the events of the document, as before.
 *
 * One range (from, to) is for all three. The gaps (no record for a while) and the bursts (a slice far above the
 * usual) the server finds in the host records are marked on the density, and listed under it: each sets the range.
 */

const NIGHT_TOOLTIP = 'Outside configured business hours'
const NO_FLAGS = {}
const HOST_TABS = ['eventlogs', 'browser', 'commands', 'endpoint', 'disk']
// The detection level has a select of its own in the toolbar.
const HIDDEN_CHIPS = ['level']

const DETECTION_FILTER_OPTIONS = [
  { value: 'all', label: 'All detections' },
  { value: 'flagged', label: 'Only flagged by SOC' },
  { value: 'high', label: 'High severity' },
  { value: 'outside', label: 'Outside hours' },
]

const SOURCE_FILTER_OPTIONS = [
  { value: 'all', label: 'All sources' },
  { value: 'sample', label: 'Samples' },
  { value: 'mail', label: 'E-mails' },
  { value: 'network', label: 'Network' },
]

const KIND_OPTIONS = [
  { value: '', label: 'All kinds (not the disk)' },
  ...Object.entries(HOST_KIND_META).map(([value, meta]) => ({ value, label: meta.label })),
]

const ROW_SEVERITY_CLASSES = {
  high: 'bg-high-soft border-l-2 border-l-high-line',
  medium: 'bg-med-soft border-l-2 border-l-med-line',
}
const FLAG_HIGHLIGHT = 'bg-accent-soft border-l-2 border-l-accent-strong'

const INPUT =
  'border border-line bg-canvas px-2 py-1 font-mono text-[13px] text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

function FlagButton({ flagged, onToggle, disabled = false }) {
  return (
    <button
      type="button"
      onClick={onToggle}
      disabled={disabled}
      aria-label={flagged ? 'Remove flag' : 'Flag as malicious'}
      title={flagged ? 'Remove flag' : 'Flag as malicious'}
      className={[
        'inline-flex items-center justify-center p-1 transition-colors disabled:cursor-not-allowed disabled:opacity-50',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
        flagged ? 'text-accent hover:text-accent-fg' : 'text-fg-muted hover:text-accent',
      ].join(' ')}
    >
      <Flag className="h-4 w-4" fill={flagged ? 'currentColor' : 'none'} />
    </button>
  )
}

/**
 * The density strip: one bar per slice of time (the empty ones too, so the bars are in their place on the time
 * axis), host records under the events of the document. A gap is a hatched band across the bars with its length;
 * a burst is a red bar.
 */
function Density({ strip, onPick, gaps = [], bursts = new Map() }) {
  if (strip.bars.length === 0) return null
  const last = strip.from + strip.bars.length * strip.width
  return (
    <div>
      <div
        role="group"
        aria-label="Events in time"
        className="relative flex h-16 items-end gap-px border border-line bg-canvas p-1"
      >
        {strip.bars.map((bar, index) => {
          const burst = bursts.get(index)
          const title = `${formatDateTime(bar.t)}: ${bar.host} host records, ${bar.docs} other events${
            burst ? ` · burst, ${burst.factor}× the usual` : ''
          }`
          return (
            <button
              key={bar.t}
              type="button"
              title={title}
              aria-label={title}
              onClick={() => onPick({ start: bar.t, end: bar.t + strip.width - 1 })}
              className="relative z-10 flex h-full min-w-[3px] flex-1 flex-col justify-end focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <span className="block w-full bg-accent" style={{ height: `${(bar.docs / strip.peak) * 100}%` }} />
              <span
                className={`block w-full ${burst ? 'bg-high-line' : 'bg-info'}`}
                style={{ height: `${(bar.host / strip.peak) * 100}%` }}
              />
            </button>
          )
        })}
        {gaps.map((band) => (
          <div
            key={band.key}
            data-gap={band.minutes}
            title={`${formatDateTime(band.from)} – ${formatDateTime(band.to)}: no records for ${durationText(band.minutes)}`}
            className="pointer-events-none absolute inset-y-1 z-0 flex items-center justify-center overflow-hidden border-x border-med-line text-[10px] text-med-fg"
            style={{
              // The bars start 0.25rem in from the edge (the padding): the band follows them.
              left: `calc(${band.left}% + ${0.5 * (0.5 - band.left / 100)}rem)`,
              width: `calc(${band.width}% - ${0.5 * (band.width / 100)}rem)`,
              backgroundImage: 'repeating-linear-gradient(135deg, var(--color-med-soft) 0 4px, transparent 4px 8px)',
            }}
          >
            {band.width > 9 && <span className="bg-canvas px-1 font-mono">gap · {durationText(band.minutes)}</span>}
          </div>
        ))}
      </div>
      <div className="mt-1 flex justify-between font-mono text-[11px] text-fg-subtle">
        <span>{formatDateTime(strip.from)}</span>
        <span>{formatDateTime(last)}</span>
      </div>
    </div>
  )
}

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

function DetectionCell({ event }) {
  const { keywordMatches, isAnomalousTime } = event.soc
  if (keywordMatches.length === 0 && !isAnomalousTime) return <span className="text-fg-muted">—</span>
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
  const { goTo, requests, take } = useNavigation()
  const rowMenu = useRowMenu(incident, { timeline: false })
  const canWrite = useCanWrite(incident)
  const { summary } = useEvidenceSummary(incident?.id)
  const flags = incident?.flags ?? NO_FLAGS
  const archived = Boolean(incident?.archivedAt)

  // The filters of the host records; `from` and `to` are the range of the whole page.
  const [filters, setFilters] = useState(() => ({
    ...(incident?.suspiciousStart != null ? { from: incident.suspiciousStart } : {}),
    ...(incident?.suspiciousEnd != null ? { to: incident.suspiciousEnd } : {}),
  }))
  const [sourceFilter, setSourceFilter] = useState('all')
  const [detectionFilter, setDetectionFilter] = useState('all')
  const [initialQuery, setInitialQuery] = useState('')
  const [resetToken, setResetToken] = useState(0)
  const [marked, setMarked] = useState(0) // bumped after a flag: the table and the figures read again
  const range = useMemo(() => ({ start: filters.from ?? null, end: filters.to ?? null }), [filters.from, filters.to])

  useEffect(() => {
    setFilters({
      ...(incident?.suspiciousStart != null ? { from: incident.suspiciousStart } : {}),
      ...(incident?.suspiciousEnd != null ? { to: incident.suspiciousEnd } : {}),
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only another incident resets the range, not an edit of its window
  }, [incident?.id])

  // "Show in the Timeline" from another tab: search for that event.
  useEffect(() => {
    if (!requests.timeline) return
    const request = take('timeline')
    if (request?.search == null) return
    setSourceFilter('all')
    setDetectionFilter('all')
    setFilters({ q: request.search })
    setInitialQuery(request.search)
    setResetToken((token) => token + 1)
  }, [requests.timeline, take])

  const setRange = useCallback(
    ({ start, end }) =>
      setFilters((held) => {
        const next = { ...held }
        if (start == null) delete next.from
        else next.from = start
        if (end == null) delete next.to
        else next.to = end
        return next
      }),
    [],
  )

  // ---- The events of the document ----
  const data = incident?.data
  const events = useMemo(() => buildTimelineEvents(data, engine), [data, engine])
  const shown = useMemo(
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
  const flaggedDocs = useMemo(() => events.reduce((sum, event) => sum + (flags[event.id] ? 1 : 0), 0), [events, flags])

  // ---- The server's view of the host records: their density and how many are flagged ----
  // Without a kind chosen the disk is left out: its $MFT and $J hold millions of records (the Kind filter switches it on).
  const kindScope = useMemo(() => (filters.kind ? {} : { kindNot: KINDS_OFF_BY_DEFAULT.join(',') }), [filters.kind])
  const [histogram, setHistogram] = useState(null)
  const [thresholds, setThresholds] = useGapThresholds()
  const [flaggedHost, setFlaggedHost] = useState(0)
  const hostTotal = HOST_TABS.reduce((sum, tab) => sum + hostCounts(summary, tab).records, 0)
  const found = summedByLevel(summary) // what the Sigma rules found in the host records, by level
  useEffect(() => {
    if (!incident?.id || archived) return undefined
    const controller = new AbortController()
    evidence
      .histogram(incident.id, {
        filters: { ...filters, ...kindScope },
        buckets: 120,
        gapMinutes: thresholds.gap,
        burstFactor: thresholds.burst,
        signal: controller.signal,
      })
      .then((answer) => setHistogram(answer))
      .catch(() => {})
    evidence
      .histogram(incident.id, { filters: { flagged: true }, buckets: 10, signal: controller.signal })
      .then((answer) => setFlaggedHost(answer?.total ?? 0))
      .catch(() => {})
    return () => controller.abort()
  }, [incident?.id, archived, filters, kindScope, hostTotal, marked, thresholds.gap, thresholds.burst])

  const strip = useMemo(() => onGrid(density(histogram, shown)), [histogram, shown])
  const marks = useMemo(
    () => ({
      gaps: thresholds.show ? (histogram?.gaps ?? []) : [],
      bursts: thresholds.show ? (histogram?.bursts ?? []) : [],
    }),
    [histogram, thresholds.show],
  )
  const bands = useMemo(() => gapBands(marks.gaps, strip), [marks, strip])
  const burstMarks = useMemo(() => burstBars(marks.bursts, strip), [marks, strip])
  const spanLabel = useMemo(() => {
    if (strip.bars.length === 0) return '—'
    const last = strip.bars[strip.bars.length - 1].t + strip.width
    const days = Math.max(1, Math.round((last - strip.from) / 86_400_000))
    return `${days} day${days === 1 ? '' : 's'}`
  }, [strip])

  // ---- The table of host records ----
  const load = useMemo(() => evidence.recordsLoader(incident?.id, kindScope), [incident?.id, kindScope])
  const toggleMark = useCallback(
    async (record) => {
      await evidence.putMark(incident.id, { key: record.key, flagged: !record.flagged, note: record.note })
      setMarked((count) => count + 1)
    },
    [incident?.id],
  )
  const hostColumns = useMemo(
    () => [
      {
        key: 'flag',
        label: '',
        className: 'w-px',
        render: (row) => <FlagButton flagged={row.flagged} disabled={!canWrite} onToggle={() => toggleMark(row)} />,
      },
      {
        key: 'time',
        label: 'Date/Time',
        order: 'time',
        render: (row) => (
          <span className="whitespace-nowrap font-mono text-xs text-fg">{row.ts ? formatDateTime(row.ts) : '—'}</span>
        ),
      },
      {
        key: 'kind',
        label: 'Source',
        filterKey: 'kind',
        stackField: 'kind',
        render: (row) => {
          const meta = HOST_KIND_META[row.kind]
          return <Badge color={meta?.color ?? 'slate'}>{meta?.label ?? row.kind}</Badge>
        },
      },
      detectionsColumn,
      {
        key: 'summary',
        label: 'Event',
        render: (row) => (
          <div className="min-w-0">
            <p className="break-all text-sm text-fg">{truncate(recordLabel(row), 120)}</p>
            {(row.channel || row.eventId || row.note) && (
              <p className="truncate font-mono text-xs text-fg-muted">
                {[row.channel, row.eventId, row.note].filter(Boolean).join(' · ')}
              </p>
            )}
          </div>
        ),
      },
      { key: 'host', label: 'Host', filterKey: 'host', stackField: 'host', hideable: true },
      { key: 'username', label: 'User', filterKey: 'username', stackField: 'username', hideable: true },
      {
        key: 'open',
        label: '',
        className: 'w-px',
        render: (row) =>
          HOST_KIND_META[row.kind] ? (
            <button
              type="button"
              onClick={() => goTo(HOST_KIND_META[row.kind].tab)}
              aria-label={`Open the page of ${HOST_KIND_META[row.kind].label}`}
              title={`Open the page of ${HOST_KIND_META[row.kind].label}`}
              className="p-1 text-fg-muted hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <ExternalLink className="h-4 w-4" aria-hidden="true" />
            </button>
          ) : null,
      },
    ],
    [canWrite, goTo, toggleMark],
  )

  // ---- The columns of the events of the document ----
  const docColumns = useMemo(
    () => [
      {
        key: 'flag',
        label: '',
        className: 'w-px',
        render: (row) => (
          <FlagButton
            flagged={Boolean(flags[row.id])}
            disabled={!canWrite}
            onToggle={() => toggleFlag(incident?.id, row.flaggable)}
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
        key: 'source',
        label: 'Source',
        sortable: true,
        sortAccessor: (row) => row.sourceLabel,
        render: (row) => (
          <Badge color={(TIMELINE_SOURCE_META[row.sourceType] ?? TIMELINE_SOURCE_META.mail).color}>
            {row.sourceLabel}
          </Badge>
        ),
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
      { key: 'detection', label: 'Detection', render: (row) => <DetectionCell event={row} /> },
    ],
    [canWrite, flags, incident?.id, toggleFlag],
  )

  const hasIncidentRange = incident?.suspiciousStart != null || incident?.suspiciousEnd != null
  const resetFilters = () => {
    setSourceFilter('all')
    setDetectionFilter('all')
    setFilters({})
    setInitialQuery('')
    setResetToken((token) => token + 1)
  }

  if (events.length === 0 && hostTotal === 0) {
    return (
      <div className="mx-auto max-w-3xl">
        <div className="border border-line bg-panel py-10">
          <EmptyState
            skull
            title="Nothing on the timeline yet"
            message={
              archived
                ? ARCHIVED_RECORDS_NOTE
                : 'The timeline merges every timestamped event of the incident: the host records and the other tabs. Add evidence there and it shows up here in chronological order.'
            }
          />
        </div>
      </div>
    )
  }

  const rangeBar = (
    <div className="flex flex-wrap items-center gap-2">
      <label className="flex items-center gap-1.5 font-mono text-xs text-fg-muted">
        From
        <input
          type="datetime-local"
          value={toLocalInput(range.start)}
          onChange={(event) => setRange({ start: fromLocalInput(event.target.value), end: range.end })}
          className={INPUT}
        />
      </label>
      <label className="flex items-center gap-1.5 font-mono text-xs text-fg-muted">
        To
        <input
          type="datetime-local"
          value={toLocalInput(range.end)}
          onChange={(event) => setRange({ start: range.start, end: fromLocalInput(event.target.value) })}
          className={INPUT}
        />
      </label>
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
      <Button variant="ghost" size="xs" icon={RotateCcw} onClick={resetFilters}>
        Reset filters
      </Button>
    </div>
  )

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={Activity} label="Timeline events" value={hostTotal + events.length} />
        <StatCard icon={Clock} label="Time span" value={spanLabel} />
        <StatCard
          icon={ShieldAlert}
          label="Detections"
          value={totalOf(found).toLocaleString('en-US')}
          tone={detectionTone(found)}
          hint={levelsText(found) || undefined}
        />
        <StatCard
          icon={Flag}
          label="Flagged"
          value={flaggedDocs + flaggedHost}
          tone={flaggedDocs + flaggedHost > 0 ? 'accent' : 'default'}
        />
      </div>

      <Card title="Events in time" icon={ListTree}>
        <div className="space-y-3">
          {rangeBar}
          <GapControls thresholds={thresholds} onChange={setThresholds} />
          <Density strip={strip} onPick={setRange} gaps={bands} bursts={burstMarks} />
          {thresholds.show && strip.bars.length > 0 && (
            <GapList gaps={marks.gaps} bursts={marks.bursts} width={histogram?.width ?? 0} onPick={setRange} />
          )}
          <p className="text-xs text-fg-muted">
            Host records (blue) and the other events of the incident (green) in the range; a red bar is a burst and a
            hatched band a gap with no host record. A bar sets the range to its slice.
          </p>
        </div>
      </Card>

      {archived ? (
        <p role="status" className="border border-line bg-panel px-4 py-3 text-sm text-fg-muted">
          {ARCHIVED_RECORDS_NOTE}
        </p>
      ) : (
        hostTotal > 0 && (
          <Card title="Host records" icon={ListTree}>
            <ServerTable
              key={`${incident.id}:${resetToken}`}
              load={load}
              columns={hostColumns}
              filters={filters}
              onFiltersChange={setFilters}
              defaultOrder="-time"
              tableKey="timeline.host"
              hideChips={HIDDEN_CHIPS}
              refreshKey={`${hostTotal}:${marked}`}
              searchPlaceholder="Search the host records…"
              emptyMessage="No host records match the current filters"
              rowClassName={(row) => (row.flagged ? FLAG_HIGHLIGHT : '')}
              toolbar={
                <div className="flex flex-wrap items-center gap-2">
                  {' '}
                  <Select
                    label="Kind"
                    value={filters.kind ?? ''}
                    onChange={(kind) => setFilters((held) => ({ ...held, kind: kind || undefined }))}
                    options={KIND_OPTIONS}
                  />{' '}
                  <span className="text-xs text-fg-muted">
                    Disk records ($MFT, $J) are millions: they show when the Kind filter is Disk.
                  </span>{' '}
                  <LevelFilter
                    filters={filters}
                    onChange={(level) => setFilters((held) => ({ ...held, level: level || undefined }))}
                  />{' '}
                </div>
              }
            />
          </Card>
        )
      )}

      {events.length > 0 && (
        <Card title="Other events" icon={ListTree}>
          <p className="mb-3 text-xs text-fg-muted">
            Samples, e-mails, captures and addresses of the incident with a time, most recent first.
          </p>
          <DataTable
            key={resetToken}
            columns={docColumns}
            data={shown}
            searchKeys={['label', 'detail', 'sourceLabel']}
            searchPlaceholder="Search these events…"
            defaultSort={{ key: 'time', dir: 'desc' }}
            rowClassName={(row) => (flags[row.id] ? FLAG_HIGHLIGHT : (ROW_SEVERITY_CLASSES[row.soc.severity] ?? ''))}
            onRowContextMenu={(event, row) => rowMenu(event, { flaggable: row.flaggable, record: row })}
            initialQuery={initialQuery}
            toolbar={
              <div className="flex flex-wrap items-center gap-2">
                <Select
                  label="Source"
                  value={sourceFilter}
                  onChange={setSourceFilter}
                  options={SOURCE_FILTER_OPTIONS}
                />
                <Select
                  label="Detections"
                  value={detectionFilter}
                  onChange={setDetectionFilter}
                  options={DETECTION_FILTER_OPTIONS}
                />
              </div>
            }
            emptyMessage="No events match the current filters"
          />
        </Card>
      )}
    </div>
  )
}
