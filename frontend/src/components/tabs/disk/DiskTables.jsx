import { useCallback, useEffect, useMemo, useState } from 'react'
import { CalendarClock, FileSearch, Flag, StickyNote, TriangleAlert } from 'lucide-react'
import { Badge, Button, DateTimeRangeFilter, Select, ServerTable } from '../../ui/index.js'
import SourceViewer from '../../evidence/SourceViewer.jsx'
import StackPanel from '../../evidence/StackPanel.jsx'
import { LevelFilter, detectionsColumn } from '../../evidence/DetectionControls.jsx'
import { FLAG_HIGHLIGHT, FlagCell, useMarks } from '../../evidence/hostTable.jsx'
import { useItemMenu } from '../../menu/useRowMenu.js'
import { ruleChipValue } from '../../../domain/detections.js'
import {
  DISK_KIND,
  MFT_CHOICES,
  MFT_FIELDS,
  MFT_SOURCE,
  MFT_TIMES,
  TIMESTOMP_HINT,
  USN_FIELDS,
  USN_SOURCE,
  isDeleted,
  mftChoiceOf,
  pathOf,
  reasonOf,
  reasonOptions,
  reasonsOf,
  streamsText,
  withMftChoice,
  withReason,
} from '../../../domain/diskPage.js'
import { neighbourRecords } from '../../../domain/eventLogSources.js'
import { withFilter } from '../../../domain/serverTable.js'
import { sizeText } from '../../../domain/transfers.js'
import { formatDateTime } from '../../../lib/time.js'
import { evidence } from '../../../services/api.js'

/*
 * The two tables of the Disk page: the entries of a $MFT and the records of a $J. Each is a ServerTable over
 * the server's records (kind disk, one source), a page at a time: the filters are the API's, nothing is
 * counted or grouped here. A row opens the original behind it in the shared viewer, which lists every field.
 */

const incidentRange = (incident) =>
  withFilter(withFilter({}, 'from', incident.suspiciousStart ?? null), 'to', incident.suspiciousEnd ?? null)

const TIME = 'whitespace-nowrap font-mono text-xs text-fg'

/** What the two tables share: the loader, the marks, the viewer and the stack panel. */
function useDiskTable({ incident, source, fields, sources, refresh, focusRule }) {
  const marks = useMarks(incident.id)
  const [filters, setFilters] = useState(() => (focusRule ? { rule: focusRule } : incidentRange(incident)))
  const [rows, setRows] = useState([])
  const [viewing, setViewing] = useState(null)
  const [stacking, setStacking] = useState(null)
  const scope = useMemo(() => ({ kind: DISK_KIND, source }), [source])
  const loader = useMemo(() => evidence.recordsLoader(incident.id, scope, fields), [incident.id, scope, fields])
  const load = useCallback(
    async (args) => {
      const page = await loader(args)
      setRows(page.items)
      return page
    },
    [loader],
  )
  // Another incident starts with its own range.
  useEffect(() => {
    setFilters(focusRule ? { rule: focusRule } : incidentRange(incident))
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only another incident resets the filters, not an edit of its window
  }, [incident.id])
  const near = viewing ? neighbourRecords(rows, viewing.id) : null
  const sourceOf = (row) => {
    const found = sources.find((item) => item.id === row.sourceId)
    return found
      ? { id: found.id, fileName: found.fileName, sha256: found.sha256, size: found.size }
      : { id: row.sourceId, fileName: '' }
  }
  const setFilter = (name, value) => setFilters((before) => withFilter(before, name, value))
  const hasRange = incident.suspiciousStart != null || incident.suspiciousEnd != null
  const range = (
    <>
      <DateTimeRangeFilter
        start={filters.from ?? null}
        end={filters.to ?? null}
        onChange={({ start, end }) => setFilters((before) => withFilter(withFilter(before, 'from', start), 'to', end))}
      />
      <Button
        variant="ghost"
        size="xs"
        icon={CalendarClock}
        disabled={!hasRange}
        title="Set the range to the incident's suspicious activity window"
        onClick={() => setFilters((before) => ({ ...before, ...incidentRange(incident) }))}
      >
        Use incident range
      </Button>
    </>
  )
  return {
    marks,
    filters,
    setFilters,
    setFilter,
    load,
    scope,
    viewing,
    setViewing,
    stacking,
    setStacking,
    near,
    sourceOf,
    range,
    refresh,
  }
}

function Overlays({ table, incident, columns, onPick }) {
  const { viewing, setViewing, stacking, setStacking, near, sourceOf, filters, scope } = table
  return (
    <>
      {stacking && (
        <StackPanel
          incidentId={incident.id}
          field={stacking}
          label={columns.find((column) => column.stackField === stacking)?.label}
          filters={{ ...filters, ...scope }}
          onClose={() => setStacking(null)}
          onPick={(value) => {
            onPick(stacking, String(value))
            setStacking(null)
          }}
        />
      )}
      {viewing && (
        <SourceViewer
          incidentId={incident.id}
          source={sourceOf(viewing)}
          record={{ id: viewing.id }}
          onClose={() => setViewing(null)}
          onPrev={near.previous ? () => setViewing(near.previous) : null}
          onNext={near.next ? () => setViewing(near.next) : null}
        />
      )}
    </>
  )
}

const sourceColumn = (setViewing) => ({
  key: 'source',
  label: 'Source',
  className: 'w-px',
  render: (row) => (
    <Button
      variant="ghost"
      size="xs"
      icon={FileSearch}
      title="Open the original behind this record"
      onClick={(event) => {
        event.stopPropagation()
        setViewing(row)
      }}
    >
      Source
    </Button>
  ),
})

const rowMenuOf = (menu, table, canWrite, title, copy) => (event, row, filterItems) =>
  menu(event, {
    title: title(row).slice(0, 80) || 'Record',
    actions: [
      ...filterItems,
      canWrite && {
        label: table.marks.flagged(row) ? 'Remove flag' : 'Flag as malicious',
        icon: Flag,
        onSelect: () => table.marks.mark(row, { flagged: !table.marks.flagged(row) }),
      },
      canWrite && { label: 'Add a note…', icon: StickyNote, onSelect: () => table.marks.addNote(row) },
      { label: 'Open the source', icon: FileSearch, onSelect: () => table.setViewing(row) },
    ].filter(Boolean),
    copy: copy(row).filter((item) => item.text),
    record: { time: row.ts, summary: row.summary },
  })

/** The entries of a $MFT. */
export function MftTable({ incident, sources, canWrite, refresh, focusRule, ruleTitles }) {
  const menu = useItemMenu(incident)
  const table = useDiskTable({ incident, source: MFT_SOURCE, fields: MFT_FIELDS, sources, refresh, focusRule })
  const { marks, filters, setFilters, setFilter, setViewing, setStacking } = table

  const columns = useMemo(
    () => [
      {
        key: 'flag',
        label: '',
        className: 'w-px',
        render: (row) => <FlagCell row={row} marks={marks} canWrite={canWrite} />,
      },
      {
        key: 'ts',
        label: 'Created (SI)',
        order: 'time',
        render: (row) => (
          <span className="inline-flex items-center gap-1.5">
            <span className={TIME}>{Number.isFinite(row.ts) ? formatDateTime(row.ts) : '—'}</span>
            {row.data?.siBeforeFn === true && (
              <span title={TIMESTOMP_HINT} className="inline-flex shrink-0">
                <TriangleAlert className="h-3.5 w-3.5 text-med" aria-label={TIMESTOMP_HINT} />
              </span>
            )}
          </span>
        ),
      },
      detectionsColumn,
      {
        key: 'path',
        label: 'Path',
        render: (row) => (
          <span className="block max-w-xl break-all font-mono text-xs text-fg" title={pathOf(row)}>
            {pathOf(row) || '—'}
          </span>
        ),
      },
      {
        key: 'size',
        label: 'Size',
        align: 'right',
        render: (row) => (
          <span className="whitespace-nowrap font-mono text-xs tabular-nums text-fg">
            {Number.isFinite(row.data?.size) ? sizeText(row.data.size) : '—'}
          </span>
        ),
      },
      {
        key: 'state',
        label: 'State',
        render: (row) => (isDeleted(row) ? <Badge color="amber">deleted</Badge> : <Badge color="slate">in use</Badge>),
      },
      {
        key: 'directory',
        label: 'Type',
        hideable: true,
        render: (row) => <span className="text-xs">{row.data?.isDirectory ? 'directory' : 'file'}</span>,
      },
      {
        key: 'streams',
        label: 'Streams',
        hideable: true,
        render: (row) => <span className="break-all font-mono text-xs">{streamsText(row.data) || '—'}</span>,
      },
      {
        key: 'zone',
        label: 'Zone id',
        hideable: true,
        align: 'right',
        render: (row) => <span className="font-mono text-xs tabular-nums">{row.data?.zoneId ?? '—'}</span>,
      },
      ...MFT_TIMES.map((time) => ({
        key: time.key,
        label: time.label,
        hideable: true,
        hiddenByDefault: true,
        render: (row) => <span className={TIME}>{row.data?.[time.key] || '—'}</span>,
      })),
      sourceColumn(setViewing),
    ],
    [marks, canWrite, setViewing],
  )

  const toolbar = (
    <div className="flex flex-wrap items-center gap-2">
      {MFT_CHOICES.map((choice) => (
        <Select
          key={choice.name}
          label={choice.label}
          value={mftChoiceOf(filters, choice.name)}
          onChange={(value) => setFilters((before) => withMftChoice(before, choice.name, value))}
          options={choice.options.map(({ value, label }) => ({ value, label }))}
        />
      ))}
      <LevelFilter filters={filters} onChange={(value) => setFilter('level', value)} />
      {table.range}
      <button
        type="button"
        aria-pressed={Boolean(filters.flagged)}
        onClick={() => setFilter('flagged', !filters.flagged)}
        className={`inline-flex items-center gap-1.5 border px-2.5 py-1.5 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${filters.flagged ? 'border-accent-strong bg-accent-soft text-accent-fg' : 'border-line text-fg-muted hover:text-fg'}`}
      >
        <Flag className="h-3.5 w-3.5" aria-hidden="true" />
        Flagged only
      </button>
    </div>
  )

  return (
    <div role="tabpanel" aria-labelledby="tab-disk-mft">
      <ServerTable
        tableKey="disk-mft"
        load={table.load}
        columns={columns}
        filters={filters}
        onFiltersChange={setFilters}
        toolbar={toolbar}
        refreshKey={refresh}
        hideChips={['level', 'dataKey', 'dataValue']}
        chipLabel={(name, value) => (name === 'rule' ? ruleChipValue(value, ruleTitles) : null)}
        defaultOrder="-time"
        searchPlaceholder="Search the paths…"
        emptyMessage="No entries match the current filters"
        rowClassName={(row) => `cursor-pointer ${marks.flagged(row) ? FLAG_HIGHLIGHT : ''}`}
        onRowClick={setViewing}
        onRowContextMenu={rowMenuOf(menu, table, canWrite, pathOf, (row) => [{ label: 'path', text: pathOf(row) }])}
        onStack={setStacking}
      />
      <Overlays
        table={table}
        incident={incident}
        columns={columns}
        onPick={(field, value) => setFilter(field, value)}
      />
    </div>
  )
}

/** The records of a $J. */
export function UsnTable({ incident, sources, canWrite, refresh, focusRule, ruleTitles }) {
  const menu = useItemMenu(incident)
  const table = useDiskTable({ incident, source: USN_SOURCE, fields: USN_FIELDS, sources, refresh, focusRule })
  const { marks, filters, setFilters, setFilter, setViewing, setStacking } = table

  const columns = useMemo(
    () => [
      {
        key: 'flag',
        label: '',
        className: 'w-px',
        render: (row) => <FlagCell row={row} marks={marks} canWrite={canWrite} />,
      },
      {
        key: 'ts',
        label: 'Time',
        order: 'time',
        render: (row) => <span className={TIME}>{Number.isFinite(row.ts) ? formatDateTime(row.ts) : '—'}</span>,
      },
      detectionsColumn,
      {
        key: 'name',
        label: 'Name',
        render: (row) => (
          <span className="block max-w-md break-all font-mono text-xs text-fg" title={row.data?.name}>
            {row.data?.name || '—'}
          </span>
        ),
      },
      {
        key: 'reasons',
        label: 'Reasons',
        render: (row) => (
          <span className="flex flex-wrap gap-1">
            {reasonsOf(row.data).map((name) => (
              <Badge key={name} color="slate">
                {name}
              </Badge>
            ))}
          </span>
        ),
      },
      {
        key: 'fileEntry',
        label: 'File entry',
        align: 'right',
        hideable: true,
        render: (row) => <span className="font-mono text-xs tabular-nums">{row.data?.fileEntry ?? '—'}</span>,
      },
      {
        key: 'parentEntry',
        label: 'Parent entry',
        align: 'right',
        hideable: true,
        render: (row) => <span className="font-mono text-xs tabular-nums">{row.data?.parentEntry ?? '—'}</span>,
      },
      sourceColumn(setViewing),
    ],
    [marks, canWrite, setViewing],
  )

  const reason = reasonOf(filters)
  const toolbar = (
    <div className="flex flex-wrap items-center gap-2">
      <Select
        label="Reason"
        value={reason}
        onChange={(value) => setFilters((before) => withReason(before, value))}
        options={reasonOptions()}
      />
      <LevelFilter filters={filters} onChange={(value) => setFilter('level', value)} />
      {table.range}
    </div>
  )

  return (
    <div role="tabpanel" aria-labelledby="tab-disk-usn">
      <ServerTable
        tableKey="disk-usn"
        load={table.load}
        columns={columns}
        filters={filters}
        onFiltersChange={setFilters}
        toolbar={toolbar}
        refreshKey={refresh}
        hideChips={['level', 'dataKey', 'dataValue']}
        chipLabel={(name, value) => (name === 'rule' ? ruleChipValue(value, ruleTitles) : null)}
        defaultOrder="-time"
        searchPlaceholder="Search the names…"
        emptyMessage="No records match the current filters"
        rowClassName={(row) => `cursor-pointer ${marks.flagged(row) ? FLAG_HIGHLIGHT : ''}`}
        onRowClick={setViewing}
        onRowContextMenu={rowMenuOf(
          menu,
          table,
          canWrite,
          (row) => row.data?.name ?? row.summary,
          (row) => [{ label: 'name', text: row.data?.name }],
        )}
        onStack={setStacking}
      />
      <Overlays
        table={table}
        incident={incident}
        columns={columns}
        onPick={(field, value) => setFilter(field, value)}
      />
    </div>
  )
}
