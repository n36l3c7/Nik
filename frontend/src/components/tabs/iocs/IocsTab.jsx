import { useCallback, useEffect, useMemo, useState } from 'react'
import { Crosshair, Download, Link2, ListPlus, RefreshCw, ScanSearch, ShieldCheck, Share2, X } from 'lucide-react'
import { Badge, Button, Card, DataTable, EmptyState, Select, StatCard } from '../../ui/index.js'
import { IocValue, useIocLookup } from '../../../context/IocLookupContext.jsx'
import { useIocLibrary } from '../../../context/IocLibraryContext.jsx'
import { useSettings } from '../../../context/SettingsContext.jsx'
import { api, apiUrl } from '../../../services/api.js'
import { indicatorRef } from '../../../domain/bulk.js'
import { IOC_TYPES, sourceLabel } from '../../../domain/iocs.js'
import { onlyFound, scanWords } from '../../../domain/indicatorsFound.js'
import { useAuth } from '../../../context/AuthContext.jsx'
import { useBulk } from '../../../context/BulkContext.jsx'
import { useToast } from '../../../context/ToastContext.jsx'
import { reputationRank, verdictMeta } from '../../../domain/enrichment.js'
import { verdictRowClass } from '../../../domain/iocLibrary.js'
import { copyText } from '../../../lib/download.js'
import { formatDateTime } from '../../../lib/time.js'

/*
 * "IOCs" tab: every indicator of compromise of the incident, gathered on the
 * server from all the other tabs (browser, commands, endpoint, event logs,
 * samples) each time the incident is saved, with the number of OTHER
 * incidents it appears in. Clicking a value opens "Where seen"; right-click
 * (or the shield button) adds it to the shared allowlist. Allowlisted values
 * (Settings → IOC allowlist) are hidden by default and never exported.
 *
 * Some are there because Nik found them by itself in the fields and the
 * context when the incident came in ("Found · <path>"). One that is there
 * for that alone can be removed, and is not found again; the line under the
 * table says what the last reading came to, reads the incident now, and
 * gives back what was removed.
 *
 * Rows are selected as in every list: "Check" and "Save as a list" act on the
 * selection when there is one, on every indicator otherwise, and the bar that
 * appears removes the found ones, tags, copies and exports what is selected.
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
  const { can } = useAuth()
  const { showToast } = useToast()
  const { askBulk } = useBulk()
  const { openExport } = useIocLibrary()
  const canWrite = can('write')
  const [found, setFound] = useState(null)
  const [reading, setReading] = useState(false)
  const [state, setState] = useState({ loading: true, iocs: [], error: null })
  const foundUrl = `/incidents/${encodeURIComponent(incident.id)}/iocs/found`
  // What was found by itself: asked again after each change, with the table.
  const act = useCallback(
    async (what, body, said) => {
      try {
        setFound(await api.post(`${foundUrl}/${what}`, body))
        const res = await api.get(`/incidents/${encodeURIComponent(incident.id)}/iocs`)
        setState({ loading: false, iocs: res?.iocs ?? [], error: null })
        if (said) showToast({ message: said })
      } catch (failure) {
        showToast({ message: failure.message })
      }
    },
    [foundUrl, incident.id, showToast],
  )
  const columns = useMemo(
    () => [
      ...BASE_COLUMNS,
      {
        key: 'actions',
        label: '',
        className: 'w-px',
        render: (row) => (
          <span className="flex items-center">
            {canWrite && onlyFound(row.sources) && (
              <button
                type="button"
                onClick={() =>
                  act('remove', { type: row.type, value: row.value }, 'Removed. It will not be found again here.')
                }
                title="Remove from this incident: it was found by itself, and will not be found again"
                aria-label={`Remove ${row.value} from this incident`}
                className="p-1 text-fg-muted hover:text-high focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <X className="h-4 w-4" />
              </button>
            )}
            {!row.allowlisted && (
              <button
                type="button"
                onClick={() => openAllowlist(row.type, row.value)}
                title="Add to the allowlist"
                aria-label={`Add ${row.value} to the allowlist`}
                className="p-1 text-fg-muted hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <ShieldCheck className="h-4 w-4" />
              </button>
            )}
          </span>
        ),
      },
    ],
    [openAllowlist, canWrite, act],
  )
  const [typeFilter, setTypeFilter] = useState('all')
  const [scope, setScope] = useState('all')
  const [showAllowlisted, setShowAllowlisted] = useState(false)

  const load = useCallback(
    (signal) => {
      api
        .get(foundUrl, { signal })
        .then((answer) => setFound(answer))
        .catch(() => {})
      return api
        .get(`/incidents/${encodeURIComponent(incident.id)}/iocs`, { signal })
        .then((res) => setState({ loading: false, iocs: res?.iocs ?? [], error: null }))
        .catch((err) => {
          if (!signal?.aborted) setState((s) => ({ ...s, loading: false, error: err?.message ?? 'Failed to load.' }))
        })
    },
    [incident.id, foundUrl],
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

  // What the bar offers for the rows that are selected. They are all on this page of the
  // browser, so they are named one by one, whatever the search and the pickers keep.
  const reload = () => load()
  const bulkActions = (rows, picked) => {
    const selection = { ids: rows.map(indicatorRef) }
    const items = { items: rows.map((row) => ({ type: row.type, value: row.value })) }
    const label = `${rows.length} selected`
    const ask = (action, title, more = {}) =>
      askBulk({
        list: 'indicators',
        action,
        title,
        selection,
        onStarted: picked.reset,
        onDone: reload,
        ...more,
      })
    return [
      ...(canWrite
        ? [
            { id: 'check', label: 'Check now…', onSelect: () => openCheck(items, label) },
            {
              id: 'tags',
              label: 'Change the tags…',
              onSelect: () => ask('tags', 'Change the tags', { form: { kind: 'tags' } }),
            },
            {
              id: 'list-new',
              label: 'Save as a list…',
              onSelect: () => openListForm({ scope: items, count: rows.length, name: incident.name }),
            },
            {
              id: 'allowlist',
              label: 'Add to the allowlist…',
              onSelect: () => ask('allowlist', 'Add to the allowlist'),
            },
            {
              id: 'remove',
              label: 'Remove from this incident…',
              onSelect: () =>
                ask('incident_remove', 'Remove from this incident', {
                  params: { incident: incident.id },
                  onDone: () => {
                    api.get(foundUrl).then(setFound, () => {})
                    reload()
                  },
                }),
            },
          ]
        : []),
      { id: 'export', label: 'Export…', onSelect: () => openExport(items, label, rows.length) },
      {
        id: 'copy',
        label: 'Copy the values',
        onSelect: async () =>
          showToast({
            message: (await copyText(rows.map((row) => row.value).join('\n')))
              ? `${rows.length} ${rows.length === 1 ? 'value' : 'values'} copied.`
              : 'The browser refused to copy.',
          }),
      },
    ]
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
            skull
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
            selectable={{
              id: indicatorRef,
              label: (row) => row.value,
              noun: 'indicators',
              filter: `${typeFilter}|${scope}|${showAllowlisted}`,
              actions: bulkActions,
            }}
            emptyMessage={state.loading ? 'Loading…' : 'No indicators match the current filters'}
          />
        )}
        {found && (
          <div
            aria-label="Indicators found by themselves"
            className="mt-4 flex flex-col gap-2 border-t border-line-soft pt-3 text-xs"
          >
            <div className="flex flex-wrap items-center gap-3">
              <p className="min-w-0 flex-1 text-fg-muted">
                <span className="text-fg">Found by themselves: {found.found.length}.</span>{' '}
                {scanWords(found.scan, found.on)}
              </p>
              {canWrite && (
                <Button
                  variant="secondary"
                  size="xs"
                  icon={ScanSearch}
                  waiting={reading}
                  onClick={async () => {
                    setReading(true)
                    await act('scan', undefined, 'The incident was read for indicators.')
                    setReading(false)
                  }}
                >
                  Find indicators now
                </Button>
              )}
            </div>
            {found.removed.length > 0 && (
              <details>
                <summary className="cursor-pointer text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent">
                  Removed, and not found again: {found.removed.length}
                </summary>
                <ul className="mt-1 flex flex-col gap-1">
                  {found.removed.map((row) => (
                    <li key={`${row.type}:${row.value}`} className="flex items-center gap-2">
                      <Badge color="slate">{IOC_TYPES[row.type]?.short ?? row.type}</Badge>
                      <span className="min-w-0 flex-1 truncate font-mono text-fg">{row.value}</span>
                      <span className="text-fg-muted">
                        removed by {row.removedBy} · read at {row.path}
                      </span>
                      {canWrite && (
                        <Button
                          variant="ghost"
                          size="xs"
                          aria-label={`Put ${row.value} back`}
                          onClick={() => act('restore', { type: row.type, value: row.value }, 'Put back.')}
                        >
                          Put back
                        </Button>
                      )}
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </div>
        )}
      </Card>
    </div>
  )
}
