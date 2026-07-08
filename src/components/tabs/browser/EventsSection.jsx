/*
 * "Browser events" section: gathers browsing history and downloads into a
 * single panel with three internal views (tabs):
 *   - "All events"        → time-ordered union of history + downloads
 *   - "Browsing history"  → visits / searches / redirects only
 *   - "Downloads"         → downloaded files only
 *
 * Every row shows the event TYPE with a dedicated icon; redirect visits link to
 * their destination page. At the top: SOC stat-cards plus the top-domains and
 * frequent-searches widgets.
 *
 * Analysts can FLAG any row as part of the malicious activity (per-row toggle),
 * narrow the list with detection / type / date-time-range filters, seed the
 * range from the incident's suspicious window, and copy any URL to the
 * clipboard from the URL/Detail cell.
 */
import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  CalendarClock,
  Check,
  Clock,
  Copy,
  Download,
  ExternalLink,
  Eye,
  Flag,
  Globe,
  History,
  RotateCcw,
} from 'lucide-react'
import { Badge, Button, Card, DataTable, EmptyState, Select, StatCard } from '../../ui/index.js'
import { useSocEngine } from '../../../context/SettingsContext.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { computeSocStats } from '../../../utils/soc.js'
import {
  buildEvents,
  buildRedirectIndex,
  redirectTarget,
  formatBytes,
} from '../../../utils/events.js'
import { extractDomain, truncate } from '../../../utils/url.js'
import { formatDateTime } from '../../../utils/time.js'
import EventTypeIcon from './EventTypeIcon.jsx'
import TopDomainsWidget from './TopDomainsWidget.jsx'
import SearchQueriesWidget from './SearchQueriesWidget.jsx'
import DateTimeRangeFilter from './DateTimeRangeFilter.jsx'

const NIGHT_TOOLTIP = 'Outside configured business hours'

const DETECTION_FILTER_OPTIONS = [
  { value: 'all', label: 'All' },
  { value: 'flagged', label: 'Only flagged by SOC' },
  { value: 'high', label: 'High severity' },
  { value: 'outside', label: 'Outside hours' },
]

const TYPE_FILTER_OPTIONS = [
  { value: 'all', label: 'All types' },
  { value: 'visit', label: 'Visit' },
  { value: 'search', label: 'Search' },
  { value: 'redirect', label: 'Redirect' },
  { value: 'download', label: 'Download' },
]

// Row highlight for SOC severity (red = high, amber = medium).
const ROW_SEVERITY_CLASSES = {
  high: 'bg-red-500/5 dark:bg-red-500/10 border-l-2 border-l-red-500',
  medium: 'bg-amber-500/5 dark:bg-amber-500/10 border-l-2 border-l-amber-500',
}

// Row highlight for entries manually flagged by the analyst (cyan, distinct
// from the red/amber SOC severity highlight).
const FLAG_HIGHLIGHT = 'bg-cyan-500/5 dark:bg-cyan-500/10 border-l-2 border-l-cyan-500'

const INTERNAL_TABS = [
  { id: 'all', label: 'All events', icon: Activity },
  { id: 'history', label: 'Browsing history', icon: History },
  { id: 'downloads', label: 'Downloads', icon: Download },
]

/* ---- Reusable cells -------------------------------------------------------- */

function TimeCell({ event }) {
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

function ExternalLinkIcon({ href }) {
  if (!href) return null
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title="Open in a new tab"
      aria-label="Open in a new tab"
      className="shrink-0 rounded text-slate-400 hover:text-cyan-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 dark:text-slate-500 dark:hover:text-cyan-400"
    >
      <ExternalLink className="h-3.5 w-3.5" />
    </a>
  )
}

/**
 * Copy-to-clipboard button, hidden until the surrounding `group` cell is
 * hovered (or the button is focused). Shows a brief check-mark after copying.
 */
function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  if (!text) return null

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    } catch {
      // Clipboard API unavailable (e.g. insecure context): ignore silently.
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
      {copied ? (
        <Check className="h-3.5 w-3.5 text-emerald-500" />
      ) : (
        <Copy className="h-3.5 w-3.5" />
      )}
    </button>
  )
}

/** Per-row flag toggle. Filled cyan when the entry is flagged. */
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
 * @param {{ incident: object, browserId: string, history?: Array, downloads?: Array }} props
 */
export default function EventsSection({ incident, browserId, history = [], downloads = [] }) {
  const engine = useSocEngine()
  const { toggleFlag } = useIncidents()

  const flags = incident?.flags ?? {}

  const [activeTab, setActiveTab] = useState('all')
  const [detectionFilter, setDetectionFilter] = useState('all')
  const [typeFilter, setTypeFilter] = useState('all')
  // Date-time range filter, seeded from the incident's suspicious window.
  const [range, setRange] = useState(() => ({
    start: incident?.suspiciousStart ?? null,
    end: incident?.suspiciousEnd ?? null,
  }))
  // Bumped by "Reset filters" to remount the DataTable and clear its internal
  // search / sort / pagination state (which the parent cannot reset directly).
  const [resetToken, setResetToken] = useState(0)

  // Reset the range whenever the active incident changes.
  useEffect(() => {
    setRange({
      start: incident?.suspiciousStart ?? null,
      end: incident?.suspiciousEnd ?? null,
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incident?.id])

  const { historyEvents, downloadEvents, allEvents } = useMemo(
    () => buildEvents({ history, downloads, engine }),
    [history, downloads, engine],
  )

  // Index used to link a redirect visit to its destination page.
  const redirectIndex = useMemo(() => buildRedirectIndex(historyEvents), [historyEvents])

  const stats = useMemo(() => computeSocStats(historyEvents), [historyEvents])

  const uniqueDomains = useMemo(() => {
    const domains = new Set()
    for (const entry of history) {
      const domain = extractDomain(entry.url)
      if (domain) domains.add(domain)
    }
    return domains.size
  }, [history])

  // Number of events (history + downloads) whose id is currently flagged.
  const flaggedCount = useMemo(
    () => allEvents.reduce((acc, event) => acc + (flags[event.id] ? 1 : 0), 0),
    [allEvents, flags],
  )

  // Dataset for the active internal tab.
  const baseData =
    activeTab === 'history' ? historyEvents : activeTab === 'downloads' ? downloadEvents : allEvents

  // Filtering pipeline: detection filter + type filter + time-range filter.
  const filtered = useMemo(
    () =>
      baseData.filter((event) => {
        // Detection filter
        if (detectionFilter === 'flagged' && !event.soc.isFlagged) return false
        if (detectionFilter === 'high' && event.soc.severity !== 'high') return false
        if (detectionFilter === 'outside' && !event.soc.isAnomalousTime) return false
        // Type filter
        if (typeFilter !== 'all' && event.eventType !== typeFilter) return false
        // Time-range filter (inclusive; a null bound leaves that side open)
        if (range.start != null && (event.time == null || event.time < range.start)) return false
        if (range.end != null && (event.time == null || event.time > range.end)) return false
        return true
      }),
    [baseData, detectionFilter, typeFilter, range],
  )

  // Columns for the active tab (rebuilt when flags change so the flag icons
  // reflect the current state).
  const columns = useMemo(
    () =>
      buildColumns(activeTab, redirectIndex, {
        incidentId: incident?.id,
        browserId,
        flags,
        toggleFlag,
      }),
    [activeTab, redirectIndex, incident?.id, browserId, flags, toggleFlag],
  )

  const searchKeys =
    activeTab === 'downloads' ? ['fileName', 'url', 'referrer'] : ['url', 'title']

  const hasIncidentRange =
    incident?.suspiciousStart != null || incident?.suspiciousEnd != null

  /** Seed the range filter from the incident's suspicious window. */
  const useIncidentRange = () =>
    setRange({
      start: incident?.suspiciousStart ?? null,
      end: incident?.suspiciousEnd ?? null,
    })

  /** Clear search, detection, type and range filters back to defaults. */
  const resetFilters = () => {
    setDetectionFilter('all')
    setTypeFilter('all')
    setRange({ start: null, end: null })
    setResetToken((token) => token + 1)
  }

  if (history.length === 0 && downloads.length === 0) {
    return (
      <EmptyState
        icon={Activity}
        title="No events to show"
        message="Load the browser history or downloads from the 'Data sources' card, or use 'Load demo data' to explore the platform."
      />
    )
  }

  const toolbar = (
    <div className="flex flex-wrap items-center gap-2">
      <Select
        value={detectionFilter}
        onChange={setDetectionFilter}
        options={DETECTION_FILTER_OPTIONS}
      />
      <Select value={typeFilter} onChange={setTypeFilter} options={TYPE_FILTER_OPTIONS} />
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
        <StatCard icon={Eye} label="Total visits" value={stats.total} />
        <StatCard icon={Globe} label="Unique domains" value={uniqueDomains} />
        <StatCard
          icon={Flag}
          label="Flagged events"
          value={flaggedCount}
          tone={flaggedCount > 0 ? 'accent' : 'default'}
          hint={stats.high > 0 ? `${stats.high} SOC high-severity` : undefined}
        />
        <StatCard
          icon={Download}
          label="Total downloads"
          value={downloads.length}
          tone={downloads.length > 0 ? 'accent' : 'default'}
        />
      </div>

      {/* Summary widgets */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <TopDomainsWidget history={history} />
        <SearchQueriesWidget history={history} engine={engine} />
      </div>

      {/* Events panel with internal tabs */}
      <Card title="Browser events" icon={Activity}>
        {/* Internal tabs */}
        <div
          role="tablist"
          aria-label="Event views"
          className="mb-4 flex flex-wrap gap-1 border-b border-slate-200 dark:border-slate-800"
        >
          {INTERNAL_TABS.map((tab) => {
            const isActive = activeTab === tab.id
            const TabIcon = tab.icon
            const count =
              tab.id === 'history'
                ? historyEvents.length
                : tab.id === 'downloads'
                  ? downloadEvents.length
                  : allEvents.length
            return (
              <button
                key={tab.id}
                type="button"
                role="tab"
                aria-selected={isActive}
                onClick={() => setActiveTab(tab.id)}
                className={[
                  '-mb-px flex items-center gap-2 whitespace-nowrap border-b-2 px-3 py-2 text-sm font-medium transition-colors',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500',
                  isActive
                    ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400'
                    : 'border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200',
                ].join(' ')}
              >
                <TabIcon className="h-4 w-4" />
                {tab.label}
                <span className="rounded-full bg-slate-100 px-1.5 text-xs tabular-nums text-slate-500 dark:bg-slate-800 dark:text-slate-400">
                  {count.toLocaleString('en-US')}
                </span>
              </button>
            )
          })}
        </div>

        {/* Event-type legend */}
        <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
          <EventTypeIcon type="visit" withLabel />
          <EventTypeIcon type="search" withLabel />
          <EventTypeIcon type="redirect" withLabel />
          <EventTypeIcon type="download" withLabel />
        </div>

        <DataTable
          key={resetToken}
          columns={columns}
          data={filtered}
          searchKeys={searchKeys}
          searchPlaceholder="Search by URL, title or file…"
          defaultSort={{ key: 'time', dir: 'desc' }}
          rowClassName={(row) =>
            flags[row.id] ? FLAG_HIGHLIGHT : (ROW_SEVERITY_CLASSES[row.soc.severity] ?? '')
          }
          toolbar={toolbar}
          emptyMessage="No events match the current filters"
        />
      </Card>
    </div>
  )
}

/* ---- Column builders per tab ---------------------------------------------- */

function buildColumns(tab, redirectIndex, { incidentId, browserId, flags, toggleFlag }) {
  // Per-row flag toggle column (leftmost).
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
            browserId,
            section: 'events',
            eventType: row.eventType,
            title: row.title || row.fileName || '',
            url: row.url || '',
            time: row.time,
          })
        }
      />
    ),
  }

  const typeColumn = {
    key: 'eventType',
    label: 'Type',
    sortable: true,
    sortAccessor: (row) => row.eventType,
    render: (row) => <EventTypeIcon type={row.eventType} withLabel />,
  }
  const timeColumn = {
    key: 'time',
    label: 'Date/Time',
    sortable: true,
    sortAccessor: (row) => row.time ?? 0,
    render: (row) => <TimeCell event={row} />,
  }
  const detectionColumn = {
    key: 'detection',
    label: 'Detection',
    render: (row) => <DetectionCell event={row} />,
  }

  if (tab === 'downloads') {
    return [
      flagColumn,
      typeColumn,
      timeColumn,
      {
        key: 'fileName',
        label: 'Downloaded file',
        sortable: true,
        sortAccessor: (row) => (row.fileName ?? '').toLowerCase(),
        render: (row) => (
          <span
            className="font-mono text-xs font-medium text-slate-800 dark:text-slate-100"
            title={row.targetPath || row.fileName}
          >
            {truncate(row.fileName, 48)}
          </span>
        ),
      },
      {
        key: 'referrer',
        label: 'From (site)',
        render: (row) => {
          const site = row.referrer || row.url
          const domain = extractDomain(site)
          return (
            <span className="group inline-flex items-center gap-1.5">
              <span className="font-mono text-xs text-slate-600 dark:text-slate-400">
                {domain || truncate(site, 40) || '—'}
              </span>
              <ExternalLinkIcon href={site} />
              <CopyButton text={site} />
            </span>
          )
        },
      },
      {
        key: 'totalBytes',
        label: 'Size',
        align: 'right',
        sortable: true,
        sortAccessor: (row) => row.totalBytes ?? 0,
        render: (row) => (
          <span className="font-mono text-xs text-slate-600 dark:text-slate-400">
            {formatBytes(row.totalBytes)}
          </span>
        ),
      },
      detectionColumn,
    ]
  }

  // Title cell shared by "Browsing history" and "All events".
  const titleColumn = {
    key: 'title',
    label: 'Title / File',
    render: (row) => {
      if (row.kind === 'download') {
        return (
          <span
            className="font-mono text-xs font-medium text-slate-800 dark:text-slate-100"
            title={row.targetPath}
          >
            {truncate(row.fileName, 44)}
          </span>
        )
      }
      const domain = extractDomain(row.url)
      return (
        <div className="min-w-0 max-w-[260px]">
          <p className="truncate text-sm text-slate-800 dark:text-slate-200">
            {row.title || (
              <span className="italic text-slate-400 dark:text-slate-500">(no title)</span>
            )}
          </p>
          {domain && <p className="truncate text-xs text-slate-500 dark:text-slate-400">{domain}</p>}
        </div>
      )
    },
  }

  // Detail / URL cell with an optional link to the redirect destination and a
  // copy-to-clipboard button revealed on hover.
  const detailColumn = {
    key: 'detail',
    label: 'URL / Detail',
    render: (row) => {
      if (row.kind === 'download') {
        const site = row.referrer || row.url
        return (
          <span className="group inline-flex items-center gap-1.5">
            <span className="font-mono text-xs text-slate-600 dark:text-slate-400">
              from {extractDomain(site) || truncate(site, 36) || '—'}
            </span>
            <ExternalLinkIcon href={site} />
            <CopyButton text={site} />
          </span>
        )
      }
      const target = redirectTarget(row, redirectIndex)
      return (
        <div className="group min-w-0">
          <span className="inline-flex items-center gap-1.5">
            <span className="break-all font-mono text-xs text-slate-600 dark:text-slate-400">
              {truncate(row.url, 64)}
            </span>
            <ExternalLinkIcon href={row.url} />
            <CopyButton text={row.url} />
          </span>
          {target && (
            // Link to the redirect destination page
            <span className="mt-0.5 flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400">
              <span aria-hidden="true">→</span>
              <a
                href={target.url}
                target="_blank"
                rel="noopener noreferrer"
                className="truncate font-mono hover:underline"
                title={`Redirect to ${target.url}`}
              >
                {extractDomain(target.url) || truncate(target.url, 40)}
              </a>
            </span>
          )}
        </div>
      )
    },
  }

  // "Browsing history" and "All events" share the same column set; the data
  // differs (history-only vs. merged with downloads).
  return [flagColumn, typeColumn, timeColumn, titleColumn, detailColumn, detectionColumn]
}
