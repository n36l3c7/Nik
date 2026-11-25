import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  CalendarClock,
  FileSearch,
  Flag,
  HelpCircle,
  Info,
  ScrollText,
  Server,
  ShieldAlert,
  Star,
  StickyNote,
} from 'lucide-react'
import { Button, DateTimeRangeFilter, Modal, Select, ServerTable, StatCard, Tabs } from '../../ui/index.js'
import SourceFiles from '../../evidence/SourceFiles.jsx'
import SourceViewer from '../../evidence/SourceViewer.jsx'
import StackPanel from '../../evidence/StackPanel.jsx'
import DetectionsSection from '../../evidence/DetectionsSection.jsx'
import { LevelFilter, detectionsColumn } from '../../evidence/DetectionControls.jsx'
import { FLAG_HIGHLIGHT, FilterInput, FlagCell, useMarks, useStackValues } from '../../evidence/hostTable.jsx'
import { useAuth } from '../../../context/AuthContext.jsx'
import { useItemMenu } from '../../menu/useRowMenu.js'
import { detectionTone, levelsText, ruleChipValue } from '../../../domain/detections.js'
import { neighbourRecords, sourceOfRecord } from '../../../domain/eventLogSources.js'
import { withFilter } from '../../../domain/serverTable.js'
import {
  SYSLOG_FIELDS,
  SYSLOG_KIND,
  SYSLOG_MATTER_FILTER,
  addressOf,
  channelLabel,
  expectedSyslog,
  matchSyslogSource,
  messageOf,
  programOf,
  syslogSourcesFor,
  syslogTitle,
  typeLabel,
} from '../../../domain/syslogSources.js'
import { formatDateTime } from '../../../lib/time.js'
import { useDetections } from '../../../lib/useDetections.js'
import { evidence } from '../../../services/api.js'

/*
 * The logs of a Linux or macOS host (section `syslog`): the auth log, the journal, the audit log and the
 * unified log, read by the worker like the event logs of Windows. The page is the same: the files (with where
 * to find each), counts from the server, then the events and the detections of the Nik rules.
 */

const NO_SOURCES = []
const SECTIONS = [
  { id: 'events', label: 'Events' },
  { id: 'detections', label: 'Detections' },
]
const BASE = { kind: SYSLOG_KIND }
const HIDDEN_CHIPS = ['level', 'type', 'dataKey', 'dataValue']

const incidentRange = (incident) =>
  withFilter(withFilter({}, 'from', incident.suspiciousStart ?? null), 'to', incident.suspiciousEnd ?? null)

function Help({ os }) {
  const [open, setOpen] = useState(false)
  const sources = syslogSourcesFor(os)
  return (
    <>
      <Button variant="ghost" size="xs" icon={HelpCircle} onClick={() => setOpen(true)}>
        Where to find these files
      </Button>
      <Modal open={open} onClose={() => setOpen(false)} title="Where to find the logs" maxWidth="max-w-3xl">
        <div className="space-y-4 text-sm text-fg-muted">
          {sources.map((item) => (
            <section key={item.key} className="space-y-1">
              <p className="font-semibold text-fg">{item.label}</p>
              <p className="break-words font-mono text-xs">{item.hint}</p>
            </section>
          ))}
        </div>
      </Modal>
    </>
  )
}

/** The events of the logs of Linux and macOS: a table of the server's records, kind syslog. */
function Events({ incident, sources, canWrite, refresh, matter, onMatterChange, focusRule, ruleTitles }) {
  const menu = useItemMenu(incident)
  const marks = useMarks(incident.id)
  const [filters, setFilters] = useState(() => (focusRule ? { rule: focusRule } : incidentRange(incident)))
  const [rows, setRows] = useState([])
  const [viewing, setViewing] = useState(null)
  const [stacking, setStacking] = useState(null)
  const channels = useStackValues(incident.id, 'channel', BASE, refresh)
  const types = useStackValues(incident.id, 'type', BASE, refresh)
  const programs = useStackValues(incident.id, 'data.program', BASE, refresh)

  // "Events that matter" is a list of types: it applies while no type was chosen.
  const scope = useMemo(
    () => (matter && !filters.type ? { ...BASE, type: SYSLOG_MATTER_FILTER } : BASE),
    [matter, filters.type],
  )
  const loader = useMemo(() => evidence.recordsLoader(incident.id, scope, SYSLOG_FIELDS), [incident.id, scope])
  const load = useCallback(
    async (args) => {
      const page = await loader(args)
      setRows(page.items)
      return page
    },
    [loader],
  )
  const setFilter = (name, value) => setFilters((before) => withFilter(before, name, value))
  // The program is a key of the record's data: the one data filter of the table.
  const program = filters.dataKey === 'program' ? String(filters.dataValue ?? '') : ''
  const setProgram = (value) =>
    setFilters((before) => {
      const { dataKey: _key, dataValue: _value, ...rest } = before
      return value ? { ...rest, dataKey: 'program', dataValue: value } : rest
    })

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
        render: (row) => (
          <span className="whitespace-nowrap font-mono text-xs text-fg">
            {Number.isFinite(row.ts) ? formatDateTime(row.ts) : '—'}
          </span>
        ),
      },
      detectionsColumn,
      {
        key: 'host',
        label: 'Host',
        filterKey: 'host',
        stackField: 'host',
        hideable: true,
        render: (row) => <span className="font-mono text-xs text-fg">{row.host || '—'}</span>,
      },
      {
        key: 'channel',
        label: 'Channel',
        filterKey: 'channel',
        stackField: 'channel',
        hideable: true,
        render: (row) => <span className="text-xs">{channelLabel(row.channel) || '—'}</span>,
      },
      {
        key: 'type',
        label: 'Type',
        filterKey: 'type',
        stackField: 'type',
        render: (row) => <span className="whitespace-nowrap text-xs">{typeLabel(row.type) || '—'}</span>,
      },
      {
        key: 'username',
        label: 'User',
        filterKey: 'username',
        stackField: 'username',
        hideable: true,
        render: (row) => <span className="whitespace-nowrap font-mono text-xs text-fg">{row.username || '—'}</span>,
      },
      {
        key: 'program',
        label: 'Program',
        stackField: 'data.program',
        hideable: true,
        render: (row) => <span className="font-mono text-xs text-fg">{programOf(row) || '—'}</span>,
      },
      {
        key: 'message',
        label: 'Message / command',
        render: (row) => (
          <span className="line-clamp-2 block max-w-xl break-all font-mono text-xs text-fg" title={messageOf(row)}>
            {messageOf(row) || '—'}
          </span>
        ),
      },
      {
        key: 'address',
        label: 'Source address',
        hideable: true,
        render: (row) => <span className="whitespace-nowrap font-mono text-xs text-fg">{addressOf(row) || '—'}</span>,
      },
      {
        key: 'source',
        label: 'Source',
        className: 'w-px',
        render: (row) => (
          <Button
            variant="ghost"
            size="xs"
            icon={FileSearch}
            title="Open the original behind this event"
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
    [marks, canWrite],
  )

  const toolbar = (
    <div className="flex flex-wrap items-center gap-2">
      <Select
        label="Channel"
        value={filters.channel ?? ''}
        onChange={(value) => setFilter('channel', value)}
        options={[{ value: '', label: 'All channels' }, ...channels.map((i) => ({ value: i.value, label: i.value }))]}
      />
      <Select
        label="Type"
        value={filters.type ?? ''}
        onChange={(value) => setFilter('type', value)}
        options={[
          { value: '', label: 'All types' },
          ...types.map((i) => ({ value: i.value, label: typeLabel(i.value) })),
        ]}
      />
      <Select
        label="Program"
        value={program}
        onChange={setProgram}
        options={[
          { value: '', label: 'All programs' },
          ...(program && !programs.some((i) => i.value === program) ? [{ value: program, label: program }] : []),
          ...programs.map((i) => ({ value: i.value, label: i.value })),
        ]}
      />
      <FilterInput label="User" value={filters.username ?? ''} onCommit={(value) => setFilter('username', value)} />
      <LevelFilter filters={filters} onChange={(value) => setFilter('level', value)} />
      <DateTimeRangeFilter
        start={filters.from ?? null}
        end={filters.to ?? null}
        onChange={({ start, end }) => setFilters((before) => withFilter(withFilter(before, 'from', start), 'to', end))}
      />
      <Button
        variant="ghost"
        size="xs"
        icon={CalendarClock}
        disabled={incident.suspiciousStart == null && incident.suspiciousEnd == null}
        title="Set the range to the incident's suspicious activity window"
        onClick={() => setFilters((before) => ({ ...before, ...incidentRange(incident) }))}
      >
        Use incident range
      </Button>
      <button
        type="button"
        aria-pressed={matter}
        title={
          matter
            ? 'Showing the events that matter (logons, failed logons, sudo, accounts, processes): click to see all'
            : 'Showing all events: click to see only the events that matter'
        }
        onClick={() => onMatterChange(!matter)}
        className={`inline-flex items-center gap-1.5 border px-2.5 py-1.5 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${matter ? 'border-accent-strong bg-accent-soft text-accent-fg' : 'border-line text-fg-muted hover:text-fg'}`}
      >
        <Star className="h-3.5 w-3.5" aria-hidden="true" />
        Events that matter
      </button>
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

  const rowMenu = (event, row, filterItems) =>
    menu(event, {
      title: messageOf(row).slice(0, 80) || 'Event',
      actions: [
        ...filterItems,
        canWrite && {
          label: marks.flagged(row) ? 'Remove flag' : 'Flag as malicious',
          icon: Flag,
          onSelect: () => marks.mark(row, { flagged: !marks.flagged(row) }),
        },
        canWrite && { label: 'Add a note…', icon: StickyNote, onSelect: () => marks.addNote(row) },
        { label: 'Open the source', icon: FileSearch, onSelect: () => setViewing(row) },
      ].filter(Boolean),
      copy: [
        { label: 'message', text: messageOf(row) },
        { label: 'user', text: row.username },
        { label: 'host', text: row.host },
        { label: 'address', text: addressOf(row) },
      ].filter((item) => item.text),
      record: { time: row.ts, type: row.type, channel: row.channel, host: row.host, user: row.username },
    })

  const near = viewing ? neighbourRecords(rows, viewing.id) : null

  return (
    <div role="tabpanel" aria-labelledby="tab-syslog-events">
      <ServerTable
        tableKey="syslog"
        load={load}
        columns={columns}
        filters={filters}
        onFiltersChange={setFilters}
        toolbar={toolbar}
        refreshKey={`${refresh}:${matter}`}
        hideChips={HIDDEN_CHIPS}
        chipLabel={(name, value) => (name === 'rule' ? ruleChipValue(value, ruleTitles) : null)}
        defaultOrder="-time"
        searchPlaceholder="Search the messages…"
        emptyMessage={
          matter
            ? 'No events that matter match the current filters: show all events to see the rest'
            : 'No events match the current filters'
        }
        rowClassName={(row) => `cursor-pointer ${marks.flagged(row) ? FLAG_HIGHLIGHT : ''}`}
        onRowClick={setViewing}
        onRowContextMenu={rowMenu}
        onStack={setStacking}
      />
      {stacking && (
        <StackPanel
          incidentId={incident.id}
          field={stacking}
          label={columns.find((column) => column.stackField === stacking)?.label}
          filters={{ ...filters, ...scope }}
          onClose={() => setStacking(null)}
          onPick={(value) => {
            if (stacking === 'data.program') setProgram(String(value))
            else setFilter(stacking, String(value))
            setStacking(null)
          }}
        />
      )}
      {viewing && (
        <SourceViewer
          incidentId={incident.id}
          source={sourceOfRecord(viewing, sources) ?? { id: viewing.sourceId, fileName: '' }}
          record={{ id: viewing.id }}
          onClose={() => setViewing(null)}
          onPrev={near.previous ? () => setViewing(near.previous) : null}
          onNext={near.next ? () => setViewing(near.next) : null}
        />
      )}
    </div>
  )
}

export default function SyslogLogs({ incident, os }) {
  const { can } = useAuth()
  const archived = Boolean(incident.archivedAt)
  const canWrite = can('write') && !archived
  const [version, setVersion] = useState(0)
  const [sources, setSources] = useState(NO_SOURCES)
  const [counts, setCounts] = useState({ records: 0, sources: 0, channels: 0, flagged: 0, matter: 0 })
  const [matter, setMatter] = useState(true)
  const [section, setSection] = useState(SECTIONS[0].id)
  const [focusRule, setFocusRule] = useState('')
  const [ruleTitles, setRuleTitles] = useState({})
  const changed = useCallback(() => setVersion((n) => n + 1), [])

  useEffect(() => {
    const controller = new AbortController()
    const { signal } = controller
    const quiet = () => null
    Promise.all([
      evidence.sources(incident.id, { kind: SYSLOG_KIND, signal }).catch(quiet),
      evidence.summary(incident.id, { signal }).catch(quiet),
      archived ? null : evidence.stack(incident.id, { field: 'channel', limit: 1, filters: BASE, signal }).catch(quiet),
      archived
        ? null
        : evidence.records(incident.id, { filters: { ...BASE, flagged: true }, limit: 1, signal }).catch(quiet),
      archived
        ? null
        : evidence
            .records(incident.id, { filters: { ...BASE, type: SYSLOG_MATTER_FILTER }, limit: 1, signal })
            .catch(quiet),
    ]).then(([listed, summary, channels, flagged, mattering]) => {
      if (signal.aborted) return
      if (listed) setSources(listed.sources)
      const mine = summary?.kinds?.[SYSLOG_KIND]
      setCounts((before) => ({
        records: mine?.records ?? before.records,
        sources: mine?.sources ?? before.sources,
        channels: channels?.distinct ?? before.channels,
        flagged: flagged?.count ?? before.flagged,
        matter: mattering?.count ?? before.matter,
      }))
    })
    return () => controller.abort()
  }, [incident.id, archived, version])

  const hasRecords = counts.records > 0
  const found = useDetections(incident.id, { kind: SYSLOG_KIND, refresh: version, enabled: !archived && hasRecords })
  const openRule = useCallback((rule) => {
    setRuleTitles((before) => ({ ...before, [rule.ruleId]: rule.title }))
    setFocusRule(rule.ruleId)
    setMatter(false)
    setSection('events')
  }, [])
  const items = SECTIONS.map((item) => ({
    ...item,
    count: item.id === 'events' ? (matter ? counts.matter : counts.records) : found.data.total,
  }))
  const expected = useMemo(() => expectedSyslog(os), [os])

  return (
    <div className="space-y-6">
      {archived && (
        <p role="status" className="flex items-start gap-2 border border-line bg-panel p-3 text-sm text-fg-muted">
          <Info className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          Archived: the records are not loaded. Take the incident out of the archive to read them again.
        </p>
      )}

      <SourceFiles
        incidentId={incident.id}
        kind={SYSLOG_KIND}
        title={syslogTitle(os)}
        expected={expected}
        match={matchSyslogSource}
        canWrite={canWrite}
        onChanged={changed}
        help={<Help os={os} />}
      />

      {!archived && hasRecords && (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
            <StatCard icon={ScrollText} label="Events kept" value={counts.records.toLocaleString('en-US')} />
            <StatCard icon={FileSearch} label="Sources" value={counts.sources.toLocaleString('en-US')} />
            <StatCard icon={Server} label="Channels" value={counts.channels.toLocaleString('en-US')} />
            <StatCard
              icon={Flag}
              label="Flagged"
              value={counts.flagged.toLocaleString('en-US')}
              tone={counts.flagged > 0 ? 'accent' : 'default'}
            />
            <StatCard
              icon={ShieldAlert}
              label="Detections"
              value={found.data.detections.toLocaleString('en-US')}
              tone={detectionTone(found.data.byLevel)}
              hint={levelsText(found.data.byLevel) || undefined}
            />
          </div>

          <div className="space-y-3">
            <Tabs
              variant="section"
              label="Parts of the logs"
              idPrefix="syslog"
              items={items}
              value={section}
              onChange={(id) => {
                setFocusRule('')
                setSection(id)
              }}
            />
            {section === 'detections' && (
              <DetectionsSection
                data={found.data}
                loading={found.loading}
                error={found.error}
                onOpen={openRule}
                noun="events"
              />
            )}
            {section === 'events' && (
              <Events
                incident={incident}
                sources={sources}
                canWrite={canWrite}
                refresh={version}
                matter={matter}
                onMatterChange={setMatter}
                focusRule={focusRule}
                ruleTitles={ruleTitles}
              />
            )}
          </div>
        </>
      )}
    </div>
  )
}
