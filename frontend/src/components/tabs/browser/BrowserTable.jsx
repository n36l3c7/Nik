import { useCallback, useMemo, useRef, useState } from 'react'
import { CalendarClock, Flag, MessageSquare, RotateCcw, X } from 'lucide-react'
import { Badge, Button, DateTimeRangeFilter, Select, ServerTable } from '../../ui/index.js'
import SourceViewer from '../../evidence/SourceViewer.jsx'
import StackPanel from '../../evidence/StackPanel.jsx'
import { useArtifacts } from '../../../context/ArtifactContext.jsx'
import { useContextMenu } from '../../../context/ContextMenuContext.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { useIocLookup } from '../../../context/IocLookupContext.jsx'
import { useNavigation } from '../../../context/NavigationContext.jsx'
import { useToast } from '../../../context/ToastContext.jsx'
import {
  ROW_FIELDS,
  SECTION_TYPES,
  dataFilterOf,
  fromOf,
  pickedFilters,
  rowText,
  summaryText,
} from '../../../domain/browserEvidence.js'
import { formatBytes } from '../../../domain/events.js'
import { indicatorFlaggable, defang } from '../../../domain/iocs.js'
import { evidenceAddress } from '../../../domain/links.js'
import { canView } from '../../../domain/sourceFiles.js'
import { withFilter } from '../../../domain/serverTable.js'
import { copyText } from '../../../lib/download.js'
import { formatDateTime } from '../../../lib/time.js'
import { extractDomain } from '../../../lib/url.js'
import { evidence } from '../../../services/api.js'

/*
 * One part of the page (Events, Bookmarks, Shortcuts): the records of a browser and a profile, whatever
 * files they come from, read from the server a page at a time. The part is the record types it asks
 * for; the Type select narrows them. The rows carry the few keys of `data` the columns and the menu need.
 */

const TYPE_OPTIONS = [
  { value: '', label: 'all' },
  { value: 'visit', label: 'visit' },
  { value: 'download', label: 'download' },
  { value: 'search', label: 'search' },
]
const TYPE_COLOURS = { visit: 'slate', download: 'cyan', search: 'violet', bookmark: 'emerald', shortcut: 'amber' }
// These filters have a control in the toolbar: they are not repeated as chips.
const TOOLBAR_FILTERS = ['type', 'from', 'to', 'flagged', 'dataKey', 'dataValue']
const FLAGGED_ROW = 'bg-accent-soft border-l-2 border-l-accent-strong'

const TITLES = {
  events: { summary: 'Title / URL', time: 'Time', search: 'Search events…' },
  bookmarks: { summary: 'Name / URL', time: 'Added', search: 'Search bookmarks…' },
  shortcuts: { summary: 'Typed text / URL', time: 'Last used', search: 'Search shortcuts…' },
}

// What a data key picked in a stack is called in its chip.
const KEY_LABELS = { domain: 'Domain', url: 'Address', title: 'Title', name: 'Name', text: 'Typed text' }

/**
 * Props: `incident`; `section` (`events`, `bookmarks`, `shortcuts`); `scope` (the filters of the browser and
 * the profile: `kind`, `sourcePrefix`, `profile`); `sources` (every file, for the viewer); `canWrite`.
 */
export default function BrowserTable({ incident, section, scope, sources, canWrite }) {
  const { openMenu, askText } = useContextMenu()
  const { toggleFlag } = useIncidents()
  const { openIoc } = useIocLookup()
  const { goTo } = useNavigation()
  const { scanUrl, openArtifact } = useArtifacts()
  const { showToast } = useToast()
  const labels = TITLES[section]
  const types = SECTION_TYPES[section].join(',')

  const [filters, setFilters] = useState({})
  const [stacking, setStacking] = useState(null) // the field of the open stack panel
  const [viewing, setViewing] = useState(null) // the row whose original is open
  const [marks, setMarks] = useState({}) // key -> { flagged, note }: what was set here, over what the page read
  const rowsRef = useRef([]) // the rows on screen, for the previous / next of the viewer

  const load = useMemo(() => {
    const read = evidence.recordsLoader(incident.id, scope, ROW_FIELDS)
    return async (args) => {
      // The part's types are the default: a type chosen in the toolbar narrows them (the base of the loader wins).
      const page = await read({ ...args, filters: { ...args.filters, type: args.filters.type || types } })
      rowsRef.current = page.items
      return page
    }
  }, [incident.id, scope, types])

  const markOf = useCallback((row) => marks[row.key] ?? { flagged: row.flagged, note: row.note }, [marks])

  // ---- Flag and note on a record ----
  const setMark = useCallback(
    async (row, changes) => {
      const next = { ...markOf(row), ...changes }
      try {
        await evidence.putMark(incident.id, { key: row.key, flagged: next.flagged, note: next.note })
        setMarks((held) => ({ ...held, [row.key]: next }))
      } catch (failure) {
        showToast({ message: failure?.message || 'The mark could not be saved.' })
      }
    },
    [incident.id, markOf, showToast],
  )
  const askNote = useCallback(
    async (row) => {
      const note = await askText({
        title: 'Note on the record',
        label: 'Note',
        placeholder: 'What it shows',
        confirm: 'Save note',
      })
      if (note) setMark(row, { note })
    },
    [askText, setMark],
  )

  // ---- The address of a record: the rows carry it, nothing is fetched ----
  const withAddress = (row, work) => async () => {
    const url = row.data?.url
    if (url) await work(url)
    else showToast({ message: 'This record has no address.' })
  }
  const copying = (what, text) => async () =>
    showToast({ message: (await copyText(text)) ? `${what} copied.` : 'The browser refused to copy.' })
  const addIndicator = (type, value) => {
    const flaggable = indicatorFlaggable(type, value)
    if (incident.flags?.[flaggable.key]) showToast({ message: `${value} is an indicator already.` })
    else toggleFlag(incident.id, flaggable)
  }
  const analyse = async (url) => {
    const address = evidenceAddress(url)
    if (!address.href) {
      showToast({ message: 'Only http and https addresses can be analysed.' })
      return
    }
    try {
      showToast({ message: `The isolated browser is visiting ${address.defanged}…` })
      const scan = await scanUrl(address.href, { incidentId: incident.id })
      openArtifact(scan.artifactId)
    } catch (failure) {
      showToast({ message: failure?.message || 'The address could not be analysed.' })
    }
  }

  const rowMenu = (event, row, filterItems) => {
    const held = markOf(row)
    const text = rowText(row, formatDateTime(row.ts))
    const flag = canWrite
      ? [
          {
            label: held.flagged ? 'Remove the flag' : 'Flag as malicious',
            icon: Flag,
            hint: 'F',
            shortcut: 'flag',
            onSelect: () => setMark(row, { flagged: !held.flagged }),
          },
          {
            label: held.note ? 'Edit the note…' : 'Add a note…',
            icon: MessageSquare,
            hint: 'C',
            shortcut: 'comment',
            onSelect: () => askNote(row),
          },
          held.note && { label: 'Remove the note', onSelect: () => setMark(row, { note: '' }) },
        ].filter(Boolean)
      : []
    const address = [
      {
        label: 'Add the address as an indicator',
        onSelect: withAddress(row, (url) => addIndicator('url', url)),
      },
      {
        label: 'Add the domain as an indicator',
        onSelect: withAddress(row, (url) => {
          const domain = extractDomain(url)
          if (domain) addIndicator('domain', domain)
          else showToast({ message: 'This address has no domain.' })
        }),
      },
      { label: 'Where else was this seen?', onSelect: withAddress(row, (url) => openIoc('url', url)) },
      { label: 'Open in URL analysis', onSelect: withAddress(row, analyse) },
    ]
    const copy = [
      { label: 'Copy the address', onSelect: withAddress(row, (url) => copying('Address', url)()) },
      {
        label: 'Copy the address defanged',
        hint: '[.]',
        onSelect: withAddress(row, (url) => copying('Defanged address', defang(url))()),
      },
      {
        label: 'Copy the domain',
        onSelect: withAddress(row, (url) => {
          const domain = extractDomain(url)
          return domain ? copying('Domain', domain)() : showToast({ message: 'This address has no domain.' })
        }),
      },
      { label: 'Copy as text', onSelect: copying('Text', text) },
    ]
    const timeline = [
      { label: 'Show in the Timeline', onSelect: () => goTo('timeline', { search: row.summary || '' }) },
    ]
    const sections = [flag, filterItems, address, copy, timeline].filter((items) => items.length > 0)
    const items = sections.flatMap((items, index) => (index === 0 ? items : ['separator', ...items]))
    openMenu(event, { title: summaryText(row).slice(0, 80) || 'Record', items })
  }

  // ---- The original behind a record ----
  const sourceOf = (row) => sources.find((source) => source.id === row.sourceId) ?? null
  const viewIndex = viewing ? rowsRef.current.findIndex((row) => row.id === viewing.id) : -1
  const neighbour = (step) => {
    const row = rowsRef.current[viewIndex + step]
    return row && sourceOf(row) ? () => setViewing(row) : null
  }

  // ---- Columns ----
  const columns = useMemo(() => {
    const list = [
      {
        key: 'flag',
        label: '',
        className: 'w-px',
        render: (row) => {
          const held = markOf(row)
          return (
            <button
              type="button"
              disabled={!canWrite}
              onClick={() => setMark(row, { flagged: !held.flagged })}
              aria-pressed={held.flagged}
              aria-label={held.flagged ? 'Remove the flag' : 'Flag as malicious'}
              title={held.flagged ? 'Remove the flag' : 'Flag as malicious'}
              className={[
                'inline-flex items-center justify-center p-1 transition-colors disabled:cursor-default',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                held.flagged ? 'text-accent hover:text-accent-fg' : 'text-fg-muted hover:text-accent',
              ].join(' ')}
            >
              <Flag className="h-4 w-4" fill={held.flagged ? 'currentColor' : 'none'} aria-hidden="true" />
            </button>
          )
        },
      },
      {
        key: 'time',
        label: labels.time,
        order: 'time',
        render: (row) => <span className="whitespace-nowrap font-mono text-xs text-fg">{formatDateTime(row.ts)}</span>,
      },
    ]
    if (section === 'events') {
      list.push({
        key: 'type',
        label: 'Type',
        filterKey: 'type',
        stackField: 'type',
        render: (row) => <Badge color={TYPE_COLOURS[row.type] ?? 'slate'}>{row.type}</Badge>,
      })
    }
    list.push(
      {
        key: 'summary',
        label: labels.summary,
        stackField: 'data.url',
        render: (row) => {
          const note = markOf(row).note
          return (
            <span className="flex min-w-0 max-w-[40rem] items-center gap-2">
              <span className="truncate font-mono text-xs text-fg" title={summaryText(row)}>
                {summaryText(row) || <span className="italic text-fg-muted">(empty)</span>}
              </span>
              {note && (
                <span title={note} className="shrink-0 text-fg-muted">
                  <MessageSquare className="h-3.5 w-3.5" aria-label={`Note: ${note}`} />
                </span>
              )}
            </span>
          )
        },
      },
      {
        key: 'domain',
        label: 'Domain',
        hideable: true,
        stackField: 'data.domain',
        render: (row) => <span className="font-mono text-xs text-fg-muted">{row.data?.domain || ''}</span>,
      },
      ...(section === 'events'
        ? [
            {
              key: 'size',
              label: 'Size',
              hideable: true,
              render: (row) => (
                <span className="whitespace-nowrap font-mono text-xs text-fg-muted">
                  {row.type === 'download' ? formatBytes(row.data?.totalBytes) : ''}
                </span>
              ),
            },
            {
              key: 'from',
              label: 'From',
              hideable: true,
              render: (row) => (
                <span className="font-mono text-xs text-fg-muted">
                  {row.type === 'download' ? defang(fromOf(row.data)) : ''}
                </span>
              ),
            },
          ]
        : []),
      {
        key: 'source',
        label: 'Source',
        hideable: true,
        render: (row) => {
          const source = sourceOf(row)
          const open = source && canView(source)
          return (
            <Button
              variant="ghost"
              size="xs"
              disabled={!open}
              title={open ? 'Show the original behind this record' : 'The original of this file is not kept'}
              onClick={() => setViewing(row)}
            >
              Source
            </Button>
          )
        },
      },
    )
    return list
    // `sourceOf` reads `sources`, which the viewer's neighbours need too.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [section, labels, markOf, canWrite, setMark, sources])

  const picked = dataFilterOf(filters)
  const incidentRange = incident.suspiciousStart != null || incident.suspiciousEnd != null
  const toolbar = (
    <div className="flex flex-wrap items-center gap-2">
      {section === 'events' && (
        <Select
          label="Type"
          value={filters.type ?? ''}
          onChange={(value) => setFilters((held) => withFilter(held, 'type', value))}
          options={TYPE_OPTIONS}
        />
      )}
      <DateTimeRangeFilter
        start={filters.from ?? null}
        end={filters.to ?? null}
        onChange={({ start, end }) => setFilters((held) => withFilter(withFilter(held, 'from', start), 'to', end))}
      />
      <Button
        variant="ghost"
        size="xs"
        icon={CalendarClock}
        disabled={!incidentRange}
        title="Set the range to the incident's suspicious activity window"
        onClick={() =>
          setFilters((held) =>
            withFilter(withFilter(held, 'from', incident.suspiciousStart ?? ''), 'to', incident.suspiciousEnd ?? ''),
          )
        }
      >
        Use incident range
      </Button>
      <Button
        variant={filters.flagged ? 'primary' : 'secondary'}
        size="xs"
        icon={Flag}
        aria-pressed={Boolean(filters.flagged)}
        onClick={() => setFilters((held) => withFilter(held, 'flagged', held.flagged ? '' : true))}
      >
        Flagged
      </Button>
      {picked && (
        <Button
          variant="secondary"
          size="xs"
          icon={X}
          title="Remove this filter"
          onClick={() => setFilters((held) => withFilter(withFilter(held, 'dataKey', ''), 'dataValue', ''))}
        >
          {`${KEY_LABELS[picked.key] ?? picked.key} = ${picked.value}`}
        </Button>
      )}
      <Button variant="ghost" size="xs" icon={RotateCcw} onClick={() => setFilters({})}>
        Reset filters
      </Button>
    </div>
  )

  const viewed = viewing ? sourceOf(viewing) : null
  return (
    <>
      <ServerTable
        load={load}
        columns={columns}
        filters={filters}
        onFiltersChange={setFilters}
        toolbar={toolbar}
        hideChips={TOOLBAR_FILTERS}
        tableKey={`browser-${section}`}
        searchPlaceholder={labels.search}
        emptyMessage="No records match the current filters"
        rowClassName={(row) => (markOf(row).flagged ? FLAGGED_ROW : '')}
        onRowContextMenu={rowMenu}
        onStack={setStacking}
      />
      {stacking && (
        <StackPanel
          incidentId={incident.id}
          field={stacking}
          label={columns.find((column) => column.stackField === stacking)?.label}
          filters={{ ...filters, ...scope, type: filters.type || types }}
          onPick={(value) => {
            setFilters((held) => ({ ...held, ...pickedFilters(stacking, value) }))
            setStacking(null)
          }}
          onClose={() => setStacking(null)}
        />
      )}
      {viewing && viewed && (
        <SourceViewer
          incidentId={incident.id}
          source={viewed}
          record={{ id: viewing.id }}
          onClose={() => setViewing(null)}
          onPrev={neighbour(-1)}
          onNext={neighbour(1)}
        />
      )}
    </>
  )
}
