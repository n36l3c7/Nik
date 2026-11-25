import { useCallback, useEffect, useMemo, useState } from 'react'
import { FileSearch, RefreshCw, X } from 'lucide-react'
import { Badge, Button, DateTimeRangeFilter, Select, ServerTable, tabId } from '../../ui/index.js'
import SourceViewer from '../../evidence/SourceViewer.jsx'
import { FilterInput } from '../../evidence/hostTable.jsx'
import LateralGraph from './LateralGraph.jsx'
import { sourceOfRecord } from '../../../domain/eventLogSources.js'
import { withFilter } from '../../../domain/serverTable.js'
import {
  OUTCOME_OPTIONS,
  TYPE_OPTIONS,
  apiFilters,
  clickText,
  graphFilters,
  logonTypeLabel,
  logonTypeName,
  outcomeOf,
  sourceText,
  userText,
  withClick,
} from '../../../domain/logons.js'
import { formatDateTime } from '../../../lib/time.js'
import { evidence } from '../../../services/api.js'

/*
 * "Logons" of the event logs: the logons and the attempts the logs show (Security 4624, 4625, 4648, 4672, 4634,
 * Terminal Services, sshd, auditd), and above them the lateral-movement graph made from the same logons. The graph
 * follows the time range, the type, the outcome and the user of the table; a click on an edge or a machine sets
 * the host and source filters of the table (the graph does not follow those: it keeps showing everything it
 * counted). The table is a ServerTable over `/logons`; it is also what a person who cannot see the graph reads.
 */

const GRAPH_DELAY_MS = 250
// These filters have a control of their own in the toolbar, not a chip.
const HIDDEN_CHIPS = ['outcome', 'logonType', 'user', 'host', 'sourceHost', 'sourceIp']

/** An address (v4 or v6) is a source address; anything else is the name of a machine. */
const looksLikeAddress = (text) => /^[0-9a-f:.]+$/i.test(text) && /[.:]/.test(text)

const rangeOf = (filters, setFilters) => ({
  start: filters.from || null,
  end: filters.to || null,
  onChange: ({ start, end }) => setFilters((before) => withFilter(withFilter(before, 'from', start), 'to', end)),
})

/**
 * @param {{ incident: object, sources: object[], reload: number, group?: string }} props
 * `sources`: the files of the section, to open the original behind a logon; `reload` changes when files were
 * added or read again; `group` is the `idPrefix` of the page's tabs (for the label of the panel).
 */
export default function LogonsSection({ incident, sources, reload, group = 'eventlogs' }) {
  const [filters, setFilters] = useState({})
  const [minCount, setMinCount] = useState(1)
  const [asked, setAsked] = useState(1) // the minimum count the graph was asked for (after a pause)
  const [again, setAgain] = useState(0)
  const [graph, setGraph] = useState({ data: null, loading: true, error: '' })
  const [viewing, setViewing] = useState(null)

  // The slider moves at once; the graph is asked for when it rests.
  useEffect(() => {
    const timer = setTimeout(() => setAsked(minCount), GRAPH_DELAY_MS)
    return () => clearTimeout(timer)
  }, [minCount])

  const forGraph = useMemo(() => graphFilters(filters, asked), [filters, asked])
  const graphKey = JSON.stringify(forGraph)
  useEffect(() => {
    const controller = new AbortController()
    setGraph((held) => ({ ...held, loading: true, error: '' }))
    evidence
      .logonGraph(incident.id, { filters: JSON.parse(graphKey), signal: controller.signal })
      .then((data) => setGraph({ data, loading: false, error: '' }))
      .catch((failure) => {
        if (failure?.name !== 'AbortError') {
          setGraph({ data: null, loading: false, error: failure?.message || 'The graph was not read.' })
        }
      })
    return () => controller.abort()
  }, [incident.id, graphKey, reload, again])

  const load = useCallback(
    async ({ cursor, limit, order, filters: asking, signal }) => {
      const page = await evidence.logons(incident.id, { filters: apiFilters(asking), order, limit, cursor, signal })
      return { items: page.logons, next: page.next, total: cursor ? undefined : page.count, capped: page.countCapped }
    },
    [incident.id],
  )

  const setFilter = (name, value) => setFilters((before) => withFilter(before, name, value))
  const setSource = (text) =>
    setFilters((before) => {
      const { sourceHost: _host, sourceIp: _ip, ...rest } = before
      return text ? { ...rest, [looksLikeAddress(text) ? 'sourceIp' : 'sourceHost']: text } : rest
    })
  const clicked = clickText(filters)

  const columns = useMemo(
    () => [
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
        key: 'outcome',
        label: 'Outcome',
        filterKey: 'outcome',
        render: (row) => {
          const outcome = outcomeOf(row.outcome)
          return <Badge color={outcome.color}>{outcome.label}</Badge>
        },
      },
      {
        key: 'user',
        label: 'User',
        filterKey: 'user',
        value: (row) => row.user,
        render: (row) => <span className="whitespace-nowrap font-mono text-xs text-fg">{userText(row) || '—'}</span>,
      },
      {
        key: 'logonType',
        label: 'Type',
        filterKey: 'logonType',
        chipLabel: logonTypeLabel,
        render: (row) => (
          <span className="whitespace-nowrap text-xs" title={row.logonType ? `Logon type ${row.logonType}` : ''}>
            {logonTypeName(row.logonType) || '—'}
          </span>
        ),
      },
      {
        key: 'source',
        label: 'Source',
        render: (row) => <span className="whitespace-nowrap font-mono text-xs text-fg">{sourceText(row) || '—'}</span>,
      },
      {
        key: 'host',
        label: 'Host',
        filterKey: 'host',
        hideable: true,
        render: (row) => <span className="font-mono text-xs text-fg">{row.host || '—'}</span>,
      },
      {
        key: 'targetHost',
        label: 'Target host',
        hideable: true,
        render: (row) => <span className="font-mono text-xs text-fg">{row.targetHost || '—'}</span>,
      },
      {
        key: 'method',
        label: 'Method',
        hideable: true,
        render: (row) => <span className="text-xs">{row.method || '—'}</span>,
      },
      {
        key: 'status',
        label: 'Status',
        hideable: true,
        render: (row) => (
          <span className="break-all font-mono text-xs" title={row.status}>
            {row.status || '—'}
          </span>
        ),
      },
      {
        key: 'open',
        label: 'Source',
        className: 'w-px',
        render: (row) => (
          <Button
            variant="ghost"
            size="xs"
            icon={FileSearch}
            title="Open the original event behind this logon"
            disabled={row.recordId === null || row.recordId === undefined}
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
    [],
  )

  const toolbar = (
    <div className="flex flex-wrap items-center gap-2">
      <Select
        label="Outcome"
        value={filters.outcome ?? ''}
        onChange={(value) => setFilter('outcome', value)}
        options={OUTCOME_OPTIONS}
      />
      <Select
        label="Type"
        value={String(filters.logonType ?? '')}
        onChange={(value) => setFilter('logonType', value)}
        options={TYPE_OPTIONS}
      />
      <FilterInput label="User" value={filters.user ?? ''} onCommit={(value) => setFilter('user', value)} />
      <FilterInput
        label="Source"
        value={filters.sourceHost ?? filters.sourceIp ?? ''}
        width="w-36"
        onCommit={setSource}
      />
      <FilterInput label="Host" value={filters.host ?? ''} onCommit={(value) => setFilter('host', value)} />
      <DateTimeRangeFilter {...rangeOf(filters, setFilters)} />
      <Button
        variant="ghost"
        size="xs"
        icon={RefreshCw}
        title="Read the table and the graph again"
        onClick={() => setAgain((n) => n + 1)}
      >
        Refresh
      </Button>
    </div>
  )

  return (
    <div role="tabpanel" aria-labelledby={tabId(group, 'logons')} className="space-y-4">
      <section aria-label="Lateral movement" className="space-y-2">
        <h3 className="m-0 text-sm font-semibold">Lateral movement</h3>
        <p className="m-0 text-xs text-fg-muted">
          An arrow goes from where a logon came (a machine, or an address) to the machine that recorded it. It follows
          the time range, type, outcome and user below. Click an arrow or a machine to filter the table to it.
        </p>
        <LateralGraph
          graph={graph.data}
          loading={graph.loading}
          error={graph.error}
          minCount={minCount}
          onMinCount={setMinCount}
          onFilter={(click) => setFilters((before) => withClick(before, click))}
        />
        {clicked && (
          <p className="m-0 flex flex-wrap items-center gap-2 text-xs text-fg-muted">
            The table shows the logons {clicked}.
            <Button variant="ghost" size="xs" icon={X} onClick={() => setFilters((before) => withClick(before, {}))}>
              Show all
            </Button>
          </p>
        )}
      </section>
      <ServerTable
        tableKey="logons"
        load={load}
        columns={columns}
        filters={filters}
        onFiltersChange={setFilters}
        toolbar={toolbar}
        refreshKey={`${reload}:${again}`}
        hideChips={HIDDEN_CHIPS}
        defaultOrder="-time"
        searchPlaceholder="Search the user, host, source or domain…"
        emptyMessage="No logon matches the current filters"
        onRowClick={setViewing}
      />
      {viewing && viewing.recordId !== null && viewing.recordId !== undefined && (
        <SourceViewer
          incidentId={incident.id}
          source={sourceOfRecord(viewing, sources) ?? { id: viewing.sourceId, fileName: '' }}
          record={{ id: viewing.recordId }}
          onClose={() => setViewing(null)}
        />
      )}
    </div>
  )
}
