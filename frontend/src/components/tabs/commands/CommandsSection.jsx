/*
 * "Commands" section of the Command History tab: the commands of all the history files of a shell, read from the server
 * (`/records`, a page at a time), with the stat cards, the filters, the "Stack values" panel on the
 * Program column and the original behind each row (the viewer). Flags and notes are marks of the server
 * (`evidence.putMark`); the detection of suspicious commands comes from the server in a later stage.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { CalendarClock, Copy, Flag, Hash, MessageSquarePlus, Terminal } from 'lucide-react'
import { Button, CopyButton, Select, ServerTable, StatCard } from '../../ui/index.js'
import StackPanel from '../../evidence/StackPanel.jsx'
import SourceViewer from '../../evidence/SourceViewer.jsx'
import DateTimeRangeFilter from '../../ui/DateTimeRangeFilter.jsx'
import { useContextMenu } from '../../../context/ContextMenuContext.jsx'
import { useToast } from '../../../context/ToastContext.jsx'
import { noTimeText, defaultOrderFor, distinctOf, lineOf } from '../../../domain/commands.js'
import { withFilter } from '../../../domain/serverTable.js'
import { copyText } from '../../../lib/download.js'
import { formatDateTime } from '../../../lib/time.js'
import { evidence } from '../../../services/api.js'

const FLAG_HIGHLIGHT = 'bg-accent-soft border-l-2 border-l-accent-strong'
const number = (n) => (n ?? 0).toLocaleString('en-US')

function FlagButton({ flagged, onToggle, disabled }) {
  const label = flagged ? 'Remove flag' : 'Flag as malicious'
  return (
    <button
      type="button"
      onClick={onToggle}
      disabled={disabled}
      aria-label={label}
      aria-pressed={flagged}
      title={label}
      className={[
        'inline-flex items-center justify-center p-1 transition-colors disabled:cursor-not-allowed',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
        flagged ? 'text-accent hover:text-accent-fg' : 'text-fg-muted hover:text-accent',
      ].join(' ')}
    >
      <Flag className="h-4 w-4" fill={flagged ? 'currentColor' : 'none'} aria-hidden="true" />
    </button>
  )
}

// The keys of `data` the worker writes for a command that the table shows.
const FIELDS = ['program', 'line']

/**
 * @param {{ incident: object, shell: object, sources: Array, canWrite: boolean, version: number }} props
 * `sources` are the files of the shell, all shown together; `version` changes when a file did.
 */
export default function CommandsSection({ incident, shell, sources, canWrite, version }) {
  const { openMenu, askText } = useContextMenu()
  const { showToast } = useToast()
  const [filters, setFilters] = useState({})
  const [range, setRange] = useState({ start: null, end: null })
  const [marks, setMarks] = useState(0) // bumped by a flag or a note: reload the rows and the counts
  const [rows, setRows] = useState([])
  const [stack, setStack] = useState(null) // the field being stacked
  const [viewing, setViewing] = useState(null) // the row whose original is open
  const [counts, setCounts] = useState({ total: null, dated: null, flagged: null })

  // What the files of the shell hold, from the server: all records, the ones with a time, the flagged.
  useEffect(() => {
    const controller = new AbortController()
    const of = (extra) =>
      evidence
        .records(incident.id, {
          filters: { kind: 'commands', source: shell.id, ...extra },
          limit: 1,
          signal: controller.signal,
        })
        .then((page) => page.count ?? 0)
    Promise.all([of({}), of({ dated: true }), of({ flagged: true })])
      .then(([total, dated, flagged]) => setCounts({ total, dated, flagged }))
      .catch(() => {})
    return () => controller.abort()
  }, [incident.id, shell.id, version, marks])

  const base = useMemo(() => {
    const kept = { kind: 'commands', source: shell.id }
    if (range.start != null) kept.from = range.start
    if (range.end != null) kept.to = range.end
    return kept
  }, [shell.id, range])
  const load = useMemo(() => {
    const loader = evidence.recordsLoader(incident.id, base, FIELDS)
    return async (args) => {
      const page = await loader(args)
      setRows(page.items)
      return page
    }
  }, [incident.id, base])

  const hasIncidentRange = incident.suspiciousStart != null || incident.suspiciousEnd != null
  const applyIncidentRange = () =>
    setRange({ start: incident.suspiciousStart ?? null, end: incident.suspiciousEnd ?? null })

  const mark = useCallback(
    async (row, changes) => {
      try {
        await evidence.putMark(incident.id, { key: row.key, flagged: row.flagged, note: row.note, ...changes })
        setMarks((n) => n + 1)
      } catch (failure) {
        showToast({ message: failure?.message || 'The flag could not be saved.' })
      }
    },
    [incident.id, showToast],
  )

  const columns = useMemo(
    () => [
      {
        key: 'flag',
        label: '',
        className: 'w-px',
        render: (row) => (
          <FlagButton
            flagged={row.flagged}
            disabled={!canWrite}
            onToggle={() => mark(row, { flagged: !row.flagged })}
          />
        ),
      },
      {
        key: 'seq',
        label: '#',
        className: 'font-mono text-fg-muted',
        render: (row) => lineOf(row) ?? '—',
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
        key: 'username',
        label: 'User',
        filterKey: 'username',
        stackField: 'username',
        hideable: true,
        render: (row) => <span className="font-mono text-xs">{row.username || '—'}</span>,
      },
      {
        key: 'summary',
        label: 'Command',
        render: (row) => (
          <div className="group flex items-start gap-1.5">
            <Terminal className="mt-0.5 h-3.5 w-3.5 shrink-0 text-violet" aria-hidden="true" />
            <code className="min-w-0 flex-1 whitespace-pre-wrap break-all font-mono text-xs text-fg">
              {row.summary}
            </code>
            <CopyButton text={row.summary} label="Copy command" hover />
          </div>
        ),
      },
      {
        key: 'program',
        label: 'Program',
        stackField: 'data.program',
        hideable: true,
        value: (row) => row.data?.program || null,
        render: (row) => <span className="font-mono text-xs">{row.data?.program || '—'}</span>,
      },
      {
        key: 'source',
        label: 'Source',
        className: 'w-px',
        render: (row) => (
          <Button variant="ghost" size="xs" onClick={() => setViewing(row)}>
            Source
          </Button>
        ),
      },
    ],
    [canWrite, mark],
  )

  const rowMenu = (event, row, filterItems) => {
    const note = async () => {
      const text = await askText({
        title: 'Note on the command',
        label: 'Note',
        placeholder: 'What it shows',
        confirm: 'Save note',
      })
      if (text) mark(row, { note: text })
    }
    const copy = async () =>
      showToast({ message: (await copyText(row.summary)) ? 'Command copied.' : 'The browser refused to copy.' })
    const items = [
      canWrite && {
        label: row.flagged ? 'Remove the flag' : 'Flag as malicious',
        icon: Flag,
        onSelect: () => mark(row, { flagged: !row.flagged }),
      },
      canWrite && { label: 'Add a note…', icon: MessageSquarePlus, onSelect: note },
      { label: 'Copy the command', icon: Copy, onSelect: copy },
      { label: 'Show the original', icon: Terminal, onSelect: () => setViewing(row) },
      ...(filterItems.length > 0 ? ['separator', ...filterItems] : []),
    ].filter(Boolean)
    openMenu(event, { title: row.summary.slice(0, 80), items })
  }

  // A click on a value of the stack. The program is a key of `data`: filtered by dataKey and dataValue.
  const pick = (value) => {
    const next =
      stack === 'data.program'
        ? withFilter(withFilter(filters, 'dataKey', 'program'), 'dataValue', value)
        : withFilter(filters, stack, value)
    setFilters(next)
    setStack(null)
  }

  const userOptions = [
    { value: '', label: 'All' },
    ...distinctOf(sources, 'username').map((v) => ({ value: v, label: v })),
  ]
  const hostOptions = [{ value: '', label: 'All' }, ...distinctOf(sources, 'host').map((v) => ({ value: v, label: v }))]

  const toolbar = (
    <div className="flex flex-wrap items-center gap-2">
      <Select
        label="User"
        value={filters.username ?? ''}
        onChange={(value) => setFilters(withFilter(filters, 'username', value))}
        options={userOptions}
      />
      <Select
        label="Host"
        value={filters.host ?? ''}
        onChange={(value) => setFilters(withFilter(filters, 'host', value))}
        options={hostOptions}
      />
      <Button
        variant={filters.flagged ? 'primary' : 'secondary'}
        size="sm"
        icon={Flag}
        aria-pressed={Boolean(filters.flagged)}
        onClick={() => setFilters(withFilter(filters, 'flagged', !filters.flagged))}
      >
        Flagged only
      </Button>
      <DateTimeRangeFilter start={range.start} end={range.end} onChange={setRange} />
      <Button
        variant="ghost"
        size="xs"
        icon={CalendarClock}
        onClick={applyIncidentRange}
        disabled={!hasIncidentRange}
        title="Set the range to the incident's suspicious activity window"
      >
        Use incident range
      </Button>
    </div>
  )

  const viewIndex = viewing ? rows.findIndex((row) => row.id === viewing.id) : -1
  const viewSource = viewing ? (sources.find((item) => item.id === viewing.sourceId) ?? sources[0]) : null
  const defaultOrder = defaultOrderFor(sources)
  const untimed = counts.total !== null && counts.total > counts.dated
  const stackFilters = { ...filters, ...base }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard icon={Terminal} label="Commands" value={counts.total === null ? '—' : number(counts.total)} />
        <StatCard
          icon={Hash}
          label="With timestamp"
          value={counts.dated === null ? '—' : number(counts.dated)}
          hint={counts.total === null ? undefined : noTimeText(shell.label, counts.dated, counts.total)}
        />
        <StatCard
          icon={Flag}
          label="Flagged"
          value={counts.flagged === null ? '—' : number(counts.flagged)}
          tone={counts.flagged > 0 ? 'accent' : 'default'}
        />
      </div>

      <ServerTable
        key={`${shell.id}|${range.start}|${range.end}|${defaultOrder}`}
        tableKey="commands"
        load={load}
        columns={columns}
        filters={filters}
        onFiltersChange={setFilters}
        toolbar={toolbar}
        refreshKey={version + marks}
        defaultOrder={defaultOrder}
        searchPlaceholder="Search commands…"
        emptyMessage="No commands match the current filters"
        rowClassName={(row) => (row.flagged ? FLAG_HIGHLIGHT : '')}
        onRowContextMenu={rowMenu}
        onStack={setStack}
      />
      {untimed && (
        <p className="text-xs text-fg-muted">
          Commands without a time come after the ones with a time; the histories without any are listed file by file,
          each in its own order.
        </p>
      )}

      {stack && (
        <StackPanel
          incidentId={incident.id}
          field={stack}
          label={columns.find((column) => column.stackField === stack)?.label}
          filters={stackFilters}
          onPick={pick}
          onClose={() => setStack(null)}
        />
      )}

      {viewing && viewSource && (
        <SourceViewer
          incidentId={incident.id}
          source={viewSource}
          record={{ id: viewing.id }}
          onClose={() => setViewing(null)}
          onPrev={viewIndex > 0 ? () => setViewing(rows[viewIndex - 1]) : null}
          onNext={viewIndex >= 0 && viewIndex < rows.length - 1 ? () => setViewing(rows[viewIndex + 1]) : null}
        />
      )}
    </div>
  )
}
