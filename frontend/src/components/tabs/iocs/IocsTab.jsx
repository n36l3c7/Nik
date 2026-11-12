import { useCallback, useEffect, useMemo, useState } from 'react'
import { Crosshair, Download, Link2, ListPlus, RefreshCw, ShieldCheck, Share2 } from 'lucide-react'
import { Badge, Button, Card, DataTable, EmptyState, Select, StatCard } from '../../ui/index.js'
import { IocValue, useIocLookup } from '../../../context/IocLookupContext.jsx'
import { useIocLibrary } from '../../../context/IocLibraryContext.jsx'
import { useSettings } from '../../../context/SettingsContext.jsx'
import { api, apiUrl } from '../../../services/api.js'
import { IOC_TYPES, sourceLabel } from '../../../domain/iocs.js'
import { reputationRank, verdictMeta } from '../../../domain/enrichment.js'
import { verdictRowClass } from '../../../domain/iocLibrary.js'
import { formatDateTime } from '../../../lib/time.js'

/*
 * "IOCs" tab: every indicator of compromise of the incident, gathered on the
 * server from all the other tabs (browser, commands, endpoint, event logs,
 * samples) each time the incident is saved, with the number of OTHER
 * incidents it appears in. Clicking a value opens "Where seen"; right-click
 * (or the shield button) adds it to the shared allowlist. Allowlisted values
 * (Settings → IOC allowlist) are hidden by default and never exported.
 */

const TYPE_OPTIONS = [
  { value: 'all', label: 'All types' },
  ...Object.entries(IOC_TYPES).map(([value, meta]) => ({ value, label: meta.label })),
]
const SCOPE_OPTIONS = [
  { value: 'all', label: 'All indicators' },
  { value: 'shared', label: 'Seen in other incidents' },
]
const EXPORTS = [
  { format: 'csv', label: 'CSV' },
  { format: 'stix', label: 'STIX 2.1' },
  { format: 'misp', label: 'MISP' },
]
// The frontend saves edits asynchronously: wait a moment before refetching.
const REFRESH_DELAY_MS = 800

const BASE_COLUMNS = [
  {
    key: 'type',
    label: 'Type',
    sortable: true,
    render: (row) => (
      <Badge color={IOC_TYPES[row.type]?.color ?? 'slate'}>{IOC_TYPES[row.type]?.short ?? row.type}</Badge>
    ),
  },
  {
    key: 'value',
    label: 'Indicator',
    sortable: true,
    render: (row) => (
      <span className="inline-flex max-w-xl items-center gap-1.5 font-mono text-xs text-fg">
        <IocValue type={row.type} value={row.value} />
        {row.allowlisted && <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-fg-subtle" aria-label="allowlisted" />}
      </span>
    ),
  },
  {
    key: 'sources',
    label: 'Seen in',
    render: (row) => (
      <div className="flex flex-wrap gap-1">
        {row.sources.map((source) => (
          <Badge key={source} color="slate">
            {sourceLabel(source)}
          </Badge>
        ))}
      </div>
    ),
  },
  {
    key: 'count',
    label: 'Times',
    align: 'right',
    sortable: true,
    render: (row) => <span className="font-mono text-xs text-fg">{row.count}</span>,
  },
  {
    key: 'firstSeen',
    label: 'First / last seen',
    sortable: true,
    sortAccessor: (row) => row.firstSeen ?? 0,
    render: (row) =>
      row.firstSeen ? (
        <span className="whitespace-nowrap font-mono text-[11px] text-fg-muted">
          {formatDateTime(row.firstSeen)}
          <br />
          {formatDateTime(row.lastSeen)}
        </span>
      ) : (
        <span className="text-fg-muted">—</span>
      ),
  },
  {
    key: 'reputation',
    label: 'Reputation',
    sortable: true,
    sortAccessor: (row) => reputationRank(row.reputation),
    render: (row) => {
      if (!row.reputation) return <span className="text-fg-muted">—</span>
      const meta = verdictMeta(row.reputation.verdict)
      return (
        <Badge
          color={meta.color}
          title={`Score ${row.reputation.score ?? 0}/100: ${row.reputation.flagged} of ${row.reputation.checked} sources flag it. Click the value for details`}
        >
          {meta.label}
          {row.reputation.flagged > 0 && ` ${row.reputation.score ?? 0}`}
        </Badge>
      )
    },
  },
  {
    key: 'otherIncidents',
    label: 'Other incidents',
    align: 'right',
    sortable: true,
    render: (row) =>
      row.otherIncidents > 0 ? (
        <span className="font-mono tabular-nums" title="Also seen in other incidents: click the value to see where">
          {row.otherIncidents}
        </span>
      ) : (
        <span className="text-fg-muted">—</span>
      ),
  },
]

export default function IocsTab({ incident }) {
  const { openAllowlist, iocMenu } = useIocLookup()
  const { openCheck, openListForm, version: libraryVersion } = useIocLibrary()
  const { iocAllowlist } = useSettings()
  const columns = useMemo(
    () => [
      ...BASE_COLUMNS,
      {
        key: 'actions',
        label: '',
        className: 'w-px',
        render: (row) =>
          row.allowlisted ? null : (
            <button
              type="button"
              onClick={() => openAllowlist(row.type, row.value)}
              title="Add to the allowlist"
              aria-label={`Add ${row.value} to the allowlist`}
              className="p-1 text-fg-muted hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <ShieldCheck className="h-4 w-4" />
            </button>
          ),
      },
    ],
    [openAllowlist],
  )
  const [state, setState] = useState({ loading: true, iocs: [], error: null })
  const [typeFilter, setTypeFilter] = useState('all')
  const [scope, setScope] = useState('all')
  const [showAllowlisted, setShowAllowlisted] = useState(false)

  const load = useCallback(
    (signal) =>
      api
        .get(`/incidents/${encodeURIComponent(incident.id)}/iocs`, { signal })
        .then((res) => setState({ loading: false, iocs: res?.iocs ?? [], error: null }))
        .catch((err) => {
          if (!signal?.aborted) setState((s) => ({ ...s, loading: false, error: err?.message ?? 'Failed to load.' }))
        }),
    [incident.id],
  )

  // Reload when the incident changes (its data was saved and reindexed).
  useEffect(() => {
    const controller = new AbortController()
    const timer = setTimeout(() => load(controller.signal), REFRESH_DELAY_MS)
    return () => {
      clearTimeout(timer)
      controller.abort()
    }
    // The allowlist changes what is hidden: reload once Settings has saved it.
    // …and when a bulk check brought new answers.
  }, [load, incident.updatedAt, iocAllowlist, libraryVersion])

  const visible = useMemo(
    () =>
      state.iocs.filter(
        (ioc) =>
          (showAllowlisted || !ioc.allowlisted) &&
          (typeFilter === 'all' || ioc.type === typeFilter) &&
          (scope === 'all' || ioc.otherIncidents > 0),
      ),
    [state.iocs, showAllowlisted, typeFilter, scope],
  )
  const stats = useMemo(() => {
    const kept = state.iocs.filter((ioc) => !ioc.allowlisted)
    return {
      total: kept.length,
      shared: kept.filter((ioc) => ioc.otherIncidents > 0).length,
      network: kept.filter((ioc) => ['ip', 'domain', 'url'].includes(ioc.type)).length,
      allowlisted: state.iocs.length - kept.length,
    }
  }, [state.iocs])

  const exportHref = (format) => {
    const query = new URLSearchParams({ format })
    if (typeFilter !== 'all') query.set('types', typeFilter)
    return apiUrl(`/incidents/${encodeURIComponent(incident.id)}/iocs/export?${query}`)
  }

  const toolbar = (
    <div className="flex flex-wrap items-center gap-2">
      <Select value={typeFilter} onChange={setTypeFilter} options={TYPE_OPTIONS} />
      <Select value={scope} onChange={setScope} options={SCOPE_OPTIONS} />
      <label className="inline-flex items-center gap-1.5 text-xs text-fg-muted">
        <input
          type="checkbox"
          checked={showAllowlisted}
          onChange={(e) => setShowAllowlisted(e.target.checked)}
          className="accent-accent"
        />
        Show allowlisted ({stats.allowlisted})
      </label>
      <Button variant="ghost" size="xs" icon={RefreshCw} onClick={() => load()}>
        Refresh
      </Button>
    </div>
  )

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={Crosshair} label="Indicators" value={stats.total} />
        <StatCard
          icon={Share2}
          label="Seen in other incidents"
          value={stats.shared}
          tone={stats.shared > 0 ? 'accent' : 'default'}
        />
        <StatCard icon={Link2} label="Network (IP, domain, URL)" value={stats.network} />
        <StatCard icon={ShieldCheck} label="Allowlisted (hidden)" value={stats.allowlisted} />
      </div>

      <Card
        title="Indicators of compromise"
        icon={Crosshair}
        actions={
          <div className="flex flex-wrap items-center gap-1.5">
            <Button
              size="xs"
              disabled={state.iocs.length === 0}
              onClick={() => openCheck({ incident: incident.id }, incident.name)}
            >
              Check all {state.iocs.length}
            </Button>
            <Button
              size="xs"
              variant="secondary"
              icon={ListPlus}
              disabled={state.iocs.length === 0}
              onClick={() =>
                openListForm({ scope: { incident: incident.id }, count: state.iocs.length, name: incident.name })
              }
            >
              Save as a list
            </Button>
            <span className="ml-2 text-xs text-fg-muted">Export</span>
            {EXPORTS.map(({ format, label }) => (
              <a
                key={format}
                href={exportHref(format)}
                className="inline-flex items-center gap-1 border border-line px-2 py-1 text-xs text-fg hover:border-accent-strong hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                title={`Download the indicators as ${label} (allowlisted values left out)`}
              >
                <Download className="h-3.5 w-3.5" /> {label}
              </a>
            ))}
          </div>
        }
      >
        <p className="mb-3 text-[11px] text-fg-muted">
          Gathered from every tab each time the incident is saved: visited hosts and downloads, command lines, endpoint
          records, event-log addresses and command lines, sample hashes and strings. Click a value to see every incident
          it appears in.
        </p>
        {state.error && <p className="mb-2 text-xs text-high">{state.error}</p>}
        {!state.loading && state.iocs.length === 0 ? (
          <EmptyState
            icon={Crosshair}
            title="No indicators yet"
            message="Import artifacts, event logs or samples in the other tabs: their indicators show up here."
          />
        ) : (
          <DataTable
            columns={columns}
            onRowContextMenu={(event, row) => iocMenu(event, row.type, row.value)}
            data={visible}
            searchKeys={['value', 'type']}
            searchPlaceholder="Search indicators…"
            defaultSort={{ key: 'reputation', dir: 'desc' }}
            rowClassName={(row) => verdictRowClass(row.reputation?.verdict)}
            toolbar={toolbar}
            emptyMessage={state.loading ? 'Loading…' : 'No indicators match the current filters'}
          />
        )}
      </Card>
    </div>
  )
}
