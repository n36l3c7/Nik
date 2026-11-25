import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { CalendarClock, Clock, Files, Flag, MessageSquarePlus, Terminal, X } from 'lucide-react'
import { Badge, Button, Modal, Select, ServerTable, StatCard, Tabs, tabId } from '../../ui/index.js'
import SourceFiles from '../../evidence/SourceFiles.jsx'
import SourceViewer from '../../evidence/SourceViewer.jsx'
import StackPanel from '../../evidence/StackPanel.jsx'
import DateTimeRangeFilter from '../../ui/DateTimeRangeFilter.jsx'
import ScriptBlock from './ScriptBlock.jsx'
import { useAuth } from '../../../context/AuthContext.jsx'
import { useContextMenu } from '../../../context/ContextMenuContext.jsx'
import { useToast } from '../../../context/ToastContext.jsx'
import { useRowMenu } from '../../menu/useRowMenu.js'
import { ARTIFACT_CATEGORIES, getArtifactCategoryById, sourceNameByKey } from '../../../config/artifacts.js'
import { getOsById, DEFAULT_OS } from '../../../config/os.js'
import {
  ENDPOINT_KIND,
  OTHER,
  categoryItems,
  categoryOfSource,
  categoryTotals,
  columnsOf,
  countsBySource,
  dataChip,
  dataOf,
  expectedSources,
  fieldsOf,
  incidentRange,
  otherOptions,
  otherSources,
  partialCategories,
  sourceFilter,
  sourceKeyOf,
  sourceOptions,
  sourcePrefix,
  statFilters,
  withData,
  withoutData,
} from '../../../domain/endpointPage.js'
import { COUNT_SHOWN_CAP } from '../../../domain/serverTable.js'
import { formatDateTime } from '../../../lib/time.js'
import { evidence } from '../../../services/api.js'

/*
 * "Endpoint Artifacts" tab (7.0): one selector tab per forensic category. A file is sent to the server,
 * the worker (parser `endpoint`) reads it, and the records come back through the evidence API. A
 * category is built from sources (config/artifacts.js, the ones of the incident's system): each is
 * a grey row of the sources table until its file is imported. The page holds no records.
 */

const SLUG = /[^a-z0-9]+/g
/** Filesystem-safe slug for the downloaded script filename. */
const slugify = (text) =>
  String(text)
    .toLowerCase()
    .replace(SLUG, '-')
    .replace(/^-+|-+$/g, '')

const FLAGGED_ROW = 'bg-accent-soft border-l-2 border-l-accent-strong'
const FLAG_OPTIONS = [
  { value: '', label: 'Flagged: any' },
  { value: 'yes', label: 'Only flagged' },
]
// The filter each stackable field of the table sets when a value is picked.
const FILTER_OF_FIELD = { host: 'host', username: 'username' }
const DATA_FIELD = 'data.'
const OTHER_CATEGORY = { id: OTHER, label: 'Other', icon: Files, sources: {} }

const count = (n, capped = false) =>
  capped ? `${COUNT_SHOWN_CAP.toLocaleString('en-US')}+` : n.toLocaleString('en-US')

/** The collection scripts of a category on the incident's system: the old tab's content, in a dialog. */
function ScriptsDialog({ category, sources, osLabel, onClose }) {
  return (
    <Modal open onClose={onClose} title={`Collection scripts — ${category.label} (${osLabel})`} maxWidth="max-w-3xl">
      <div className="space-y-4">
        {sources
          .filter((source) => source.mode !== 'file' && source.script)
          .map((source) => (
            <div key={source.key} className="space-y-1">
              <p className="text-sm font-semibold text-fg">{source.name}</p>
              <p className="break-all font-mono text-[11px] text-fg-muted">{source.path}</p>
              {source.tool && <p className="text-[11px] text-fg-muted">{source.tool}</p>}
              <p className="inline-flex items-center gap-1 text-[11px] font-medium text-accent">
                <Terminal className="h-3 w-3" aria-hidden="true" />
                Collection script ({source.script.lang === 'powershell' ? 'PowerShell' : 'Bash'}); import the CSV it
                writes
              </p>
              <ScriptBlock script={source.script} filename={`collect-${category.id}-${slugify(source.name)}`} />
            </div>
          ))}
      </div>
    </Modal>
  )
}

/** The records of a category (all its sources, or the one chosen), with their filters, stat cards and the Source viewer. */
function Records({ incident, category, os, sources, counts, reloadKey, reload, canWrite }) {
  const isOther = category.id === OTHER
  const prefix = sourcePrefix(os, category.id)
  const otherNames = useMemo(
    () => [...new Set(otherSources(sources, os, ARTIFACT_CATEGORIES).map((source) => source.source))],
    [sources, os],
  )
  const options = useMemo(
    () => (isOther ? otherOptions(otherNames, counts) : sourceOptions(category, os, counts)),
    [isOther, otherNames, category, os, counts],
  )
  const [chosen, setChosen] = useState('')
  // "Other" has no prefix to stand for all of it: it shows one source at a time.
  const known = options.some((option) => option.value === chosen)
  const source = known ? chosen : isOther ? (options[0]?.value ?? '') : ''
  const scope = useMemo(() => (isOther ? { source } : sourceFilter(prefix, source)), [isOther, prefix, source])
  const fields = useMemo(() => fieldsOf(category.id), [category.id])
  const dataColumns = columnsOf(category.id)
  const [filters, setFilters] = useState(() => {
    const range = incidentRange(incident)
    return range ? { from: range.from, to: range.to } : {}
  })
  const [hosts, setHosts] = useState([])
  const [stats, setStats] = useState(null)
  const [viewing, setViewing] = useState(null)
  const [stackField, setStackField] = useState('')
  const rowsRef = useRef([])
  const { askText } = useContextMenu()
  const { showToast } = useToast()
  const rowMenu = useRowMenu(incident)
  const names = useMemo(() => sourceNameByKey(category), [category])

  const base = useMemo(() => ({ ...filters, kind: ENDPOINT_KIND, ...scope }), [filters, scope])
  const baseKey = JSON.stringify(base)

  // The stat cards follow the filters in force.
  useEffect(() => {
    const controller = new AbortController()
    const asked = statFilters(JSON.parse(baseKey))
    const ask = (filtersOf) =>
      evidence.records(incident.id, {
        filters: filtersOf,
        limit: 1,
        signal: controller.signal,
      })
    Promise.all([ask(asked.entries), ask(asked.timed), ask(asked.flagged)])
      .then(([all, timed, flagged]) =>
        setStats({
          entries: count(all.count ?? 0, all.countCapped),
          timed: count(timed.count ?? 0, timed.countCapped),
          flagged: flagged.count ?? 0,
        }),
      )
      .catch((failure) => {
        if (failure?.name !== 'AbortError') setStats(null)
      })
    return () => controller.abort()
  }, [incident.id, baseKey, reloadKey])

  // The hosts of this source, for the host filter.
  useEffect(() => {
    const controller = new AbortController()
    evidence
      .stack(incident.id, {
        field: 'host',
        filters: { kind: ENDPOINT_KIND, ...scope },
        signal: controller.signal,
      })
      .then((answer) => setHosts(answer.values.map((item) => item.value)))
      .catch(() => {})
    return () => controller.abort()
  }, [incident.id, scope, reloadKey])

  const load = useCallback(
    async (args) => {
      const page = await evidence.recordsLoader(incident.id, { kind: ENDPOINT_KIND, ...scope }, fields)(args)
      if (!args.signal?.aborted) rowsRef.current = page.items
      return page
    },
    [incident.id, scope, fields],
  )

  const mark = async (row, changes) => {
    try {
      await evidence.putMark(incident.id, {
        key: row.key,
        flagged: row.flagged,
        note: row.note,
        ...changes,
      })
      reload()
    } catch (failure) {
      showToast({
        message: failure?.message || 'The mark could not be saved.',
      })
    }
  }
  const toggleFlag = (row) => mark(row, { flagged: !row.flagged })
  const comment = async (row) => {
    const note = await askText({
      title: 'Comment on the record',
      label: row.flagged ? 'Comment' : 'Comment (the record is flagged too)',
      placeholder: 'What it shows',
      confirm: 'Save comment',
    })
    if (note) mark(row, { flagged: true, note })
  }

  const onRowContextMenu = (event, row, filterItems) =>
    rowMenu(event, {
      title: row.summary,
      actions: [
        canWrite && {
          label: row.flagged ? 'Remove the flag' : 'Flag as malicious',
          icon: Flag,
          onSelect: () => toggleFlag(row),
        },
        canWrite && {
          label: 'Add a comment…',
          icon: MessageSquarePlus,
          onSelect: () => comment(row),
        },
        ...filterItems,
      ],
      text: row.summary,
      record: row,
    })

  const openSource = (row) => {
    const source = sources.find((item) => item.id === row.sourceId)
    setViewing({
      row,
      source: source ?? { id: row.sourceId, fileName: row.summary },
    })
  }
  const step = (delta) => {
    const rows = rowsRef.current
    const at = rows.findIndex((row) => row.id === viewing?.row.id)
    const next = rows[at + delta]
    if (next) openSource(next)
  }
  const at = rowsRef.current.findIndex((row) => row.id === viewing?.row.id)

  const columns = [
    {
      key: 'flag',
      label: '',
      className: 'w-px',
      render: (row) => (
        <button
          type="button"
          disabled={!canWrite}
          onClick={() => toggleFlag(row)}
          aria-label={row.flagged ? 'Remove the flag' : 'Flag as malicious'}
          title={row.flagged ? 'Remove the flag' : 'Flag as malicious'}
          className={[
            'inline-flex items-center justify-center p-1 transition-colors',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
            row.flagged ? 'text-accent hover:text-accent-fg' : 'text-fg-muted hover:text-accent',
          ].join(' ')}
        >
          <Flag className="h-4 w-4" fill={row.flagged ? 'currentColor' : 'none'} aria-hidden="true" />
        </button>
      ),
    },
    {
      key: 'ts',
      label: 'Time',
      order: 'time',
      render: (row) => (
        <span className="whitespace-nowrap font-mono text-xs text-fg">{row.ts ? formatDateTime(row.ts) : '—'}</span>
      ),
    },
    {
      key: 'type',
      label: 'Source',
      stackField: 'source',
      render: (row) => <Badge color="slate">{names[row.type] ?? row.type}</Badge>,
    },
    ...(dataColumns.length > 0
      ? dataColumns.map((column, index) => ({
          key: `${DATA_FIELD}${column.key}`,
          label: column.label,
          align: column.align,
          stackField: `${DATA_FIELD}${column.key}`,
          hideable: index > 0,
          render: (row) => (
            <span className={column.mono ? 'break-all font-mono text-xs text-fg' : 'break-words text-xs text-fg'}>
              {dataOf(row, column.key) || '—'}
              {index === 0 && row.note && <span className="ml-2 font-sans text-fg-muted">— {row.note}</span>}
            </span>
          ),
        }))
      : [
          {
            // A file read before 7.0 names no category: the list carries the worker's summary.
            key: 'summary',
            label: 'Entry',
            render: (row) => (
              <span className="break-all font-mono text-xs text-fg" title={row.summary}>
                {row.summary || '—'}
                {row.note && <span className="ml-2 font-sans text-fg-muted">— {row.note}</span>}
              </span>
            ),
          },
        ]),
    {
      key: 'host',
      label: 'Host',
      filterKey: 'host',
      stackField: 'host',
      hideable: true,
      render: (row) => <span className="font-mono text-xs">{row.host || '—'}</span>,
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
      key: 'view',
      label: '',
      className: 'w-px',
      render: (row) => (
        <Button variant="ghost" size="xs" onClick={() => openSource(row)}>
          Source
        </Button>
      ),
    },
  ]

  const hasRange = incidentRange(incident) !== null
  const toolbar = (
    <div className="flex flex-wrap items-center gap-2">
      <Select label="Source" value={source} onChange={setChosen} options={options} />
      <Select
        label="Host"
        value={filters.host ?? ''}
        onChange={(host) => setFilters((held) => ({ ...held, host }))}
        options={[{ value: '', label: 'any' }, ...hosts.map((host) => ({ value: host, label: host }))]}
      />
      <Select
        value={filters.flagged ? 'yes' : ''}
        onChange={(value) => setFilters((held) => ({ ...held, flagged: value === 'yes' }))}
        options={FLAG_OPTIONS}
      />
      <DateTimeRangeFilter
        start={filters.from ?? null}
        end={filters.to ?? null}
        onChange={({ start, end }) => setFilters((held) => ({ ...held, from: start, to: end }))}
      />
      <Button
        variant="ghost"
        size="xs"
        icon={CalendarClock}
        disabled={!hasRange}
        title="Set the range to the incident's suspicious activity window"
        onClick={() => {
          const range = incidentRange(incident)
          setFilters((held) => ({ ...held, from: range.from, to: range.to }))
        }}
      >
        Use incident range
      </Button>
    </div>
  )

  const pick = (value) => {
    if (stackField === 'source') setChosen(String(value))
    else if (stackField.startsWith(DATA_FIELD)) {
      setFilters((held) => withData(held, stackField.slice(DATA_FIELD.length), value))
    } else if (FILTER_OF_FIELD[stackField]) {
      setFilters((held) => ({ ...held, [FILTER_OF_FIELD[stackField]]: value }))
    }
    setStackField('')
  }
  const chip = dataChip(filters, dataColumns)

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard icon={category.icon} label="Entries" value={stats?.entries ?? '—'} />
        <StatCard icon={Clock} label="With timestamp" value={stats?.timed ?? '—'} />
        <StatCard
          icon={Flag}
          label="Flagged"
          value={stats?.flagged ?? '—'}
          tone={stats?.flagged > 0 ? 'accent' : 'default'}
        />
      </div>

      <ServerTable
        load={load}
        columns={columns}
        filters={filters}
        onFiltersChange={setFilters}
        toolbar={toolbar}
        hideChips={['dataKey', 'dataValue']}
        filterChips={
          chip ? (
            <span className="inline-flex items-center gap-1 border border-accent-strong bg-accent-soft py-0.5 pl-2 pr-1 font-mono text-xs text-accent-fg">
              <span className="max-w-64 truncate">{chip}</span>
              <button
                type="button"
                aria-label={`Remove the filter ${chip}`}
                onClick={() => setFilters((held) => withoutData(held))}
                className="p-0.5 hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <X className="h-3 w-3" aria-hidden="true" />
              </button>
            </span>
          ) : null
        }
        tableKey="endpoint-artifacts"
        defaultOrder="-time"
        refreshKey={reloadKey}
        rowKey={(row) => row.id}
        rowClassName={(row) => (row.flagged ? FLAGGED_ROW : '')}
        onRowContextMenu={onRowContextMenu}
        onStack={setStackField}
        emptyMessage="No records match the current filters"
        searchPlaceholder={`Search ${category.label.toLowerCase()}…`}
      />

      {stackField && (
        <StackPanel
          incidentId={incident.id}
          field={stackField}
          label={columns.find((column) => column.stackField === stackField)?.label}
          filters={base}
          onPick={pick}
          onClose={() => setStackField('')}
        />
      )}
      {viewing && (
        <SourceViewer
          incidentId={incident.id}
          source={viewing.source}
          record={{ id: viewing.row.id }}
          onClose={() => setViewing(null)}
          onPrev={at > 0 ? () => step(-1) : null}
          onNext={at >= 0 && at < rowsRef.current.length - 1 ? () => step(1) : null}
        />
      )}
    </div>
  )
}

export default function EndpointArtifactsTab({ incident }) {
  const { can } = useAuth()
  const archived = Boolean(incident.archivedAt)
  const canWrite = can('write') && !archived

  const [categoryId, setCategoryId] = useState(ARTIFACT_CATEGORIES[0].id)
  const [counts, setCounts] = useState(null) // records per source name, from the server
  const [sources, setSources] = useState([])
  const [reloadKey, setReloadKey] = useState(0)
  const [addAs, setAddAs] = useState('')
  const [showScripts, setShowScripts] = useState(false)
  const [fileView, setFileView] = useState(null) // a source opened whole in the viewer
  const reload = useCallback(() => setReloadKey((n) => n + 1), [])

  const os = getOsById(incident.os) ? incident.os : DEFAULT_OS
  const osLabel = getOsById(os)?.label ?? os
  const others = useMemo(() => otherSources(sources, os, ARTIFACT_CATEGORIES), [sources, os])
  const hasOther = others.length > 0
  const isOther = categoryId === OTHER && hasOther
  const category = isOther ? OTHER_CATEGORY : (getArtifactCategoryById(categoryId) ?? ARTIFACT_CATEGORIES[0])
  const categorySources = useMemo(() => category.sources?.[os] ?? [], [category, os])
  const expected = useMemo(() => expectedSources(category, os), [category, os])

  // Counts of the selector, and the files (for the dots and the Source viewer): the server's, not a copy.
  useEffect(() => {
    const controller = new AbortController()
    evidence
      .sources(incident.id, { kind: ENDPOINT_KIND, signal: controller.signal })
      .then((answer) => setSources(answer.sources))
      .catch(() => {})
    if (archived) {
      setCounts({})
    } else {
      evidence
        .stack(incident.id, {
          field: 'source',
          filters: { kind: ENDPOINT_KIND },
          limit: 100,
          signal: controller.signal,
        })
        .then((answer) => setCounts(countsBySource(answer.values)))
        .catch(() => setCounts((held) => held ?? {}))
    }
    return () => controller.abort()
  }, [incident.id, archived, reloadKey])

  const totals = useMemo(() => categoryTotals(ARTIFACT_CATEGORIES, os, counts ?? {}), [os, counts])
  const items = useMemo(
    () => categoryItems(ARTIFACT_CATEGORIES, totals, partialCategories(sources, os, ARTIFACT_CATEGORIES), hasOther),
    [totals, sources, os, hasOther],
  )

  // The files of the page go to the source chosen here: the system, the category and the id.
  const target = expected.some((item) => item.key === addAs) ? addAs : (expected[0]?.key ?? '')
  const uploadParams = useMemo(
    () => (target ? { source: `${sourcePrefix(os, category.id)}${target}` } : null),
    [os, category.id, target],
  )
  const keepOfCategory = useCallback(
    (source) =>
      isOther
        ? categoryOfSource(source.source, os, ARTIFACT_CATEGORIES) === OTHER
        : sourceKeyOf(source, os, category.id) !== null,
    [isOther, os, category.id],
  )
  const matchSource = useCallback((source) => sourceKeyOf(source, os, category.id), [os, category.id])
  const hasScripts = categorySources.some((source) => source.mode !== 'file' && source.script)

  const help = (
    <>
      {canWrite && expected.length > 0 && (
        <Select
          label="Add files as"
          value={target}
          onChange={setAddAs}
          options={expected.map((item) => ({
            value: item.key,
            label: item.label,
          }))}
        />
      )}
      {hasScripts && (
        <Button variant="ghost" size="xs" icon={Terminal} onClick={() => setShowScripts(true)}>
          Collection scripts
        </Button>
      )}
    </>
  )

  return (
    <div className="space-y-6">
      <Tabs
        variant="selector"
        label="Artifact category"
        idPrefix="endpoint"
        items={items}
        value={category.id}
        onChange={setCategoryId}
      />

      <div role="tabpanel" aria-labelledby={tabId('endpoint', category.id)} className="space-y-6">
        {!isOther && categorySources.length === 0 && (
          <p className="border border-line bg-panel p-4 text-sm text-fg-muted">
            No fully-custom collection method for <strong>{category.label.toLowerCase()}</strong> on {osLabel}: the
            standard artifacts here require third-party DFIR parsers, so this category is empty for this host OS. Switch
            the incident OS, or use another tab.
          </p>
        )}
        <SourceFiles
          incidentId={incident.id}
          kind={ENDPOINT_KIND}
          filter={keepOfCategory}
          uploadParams={uploadParams}
          expected={expected}
          match={matchSource}
          title={`Sources — ${category.label} (${osLabel})`}
          help={help}
          canWrite={canWrite && categorySources.length > 0 && !isOther}
          onChanged={reload}
          onView={setFileView}
        />

        {archived && (
          <p className="border border-line bg-panel p-4 text-sm text-fg-muted">
            Archived: the records are not loaded. Take the incident out of the archive to read them again.
          </p>
        )}
        {!archived && counts !== null && (totals[category.id] ?? 0) > 0 && (
          <Records
            key={`${incident.id}:${category.id}`}
            incident={incident}
            category={category}
            os={os}
            sources={sources}
            counts={counts}
            reloadKey={reloadKey}
            reload={reload}
            canWrite={canWrite}
          />
        )}
      </div>

      {fileView && <SourceViewer incidentId={incident.id} source={fileView} onClose={() => setFileView(null)} />}

      {showScripts && (
        <ScriptsDialog
          category={category}
          sources={categorySources}
          osLabel={osLabel}
          onClose={() => setShowScripts(false)}
        />
      )}
    </div>
  )
}
