import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle,
  CircleDot,
  Columns3,
  Download,
  FileText,
  FolderOpen,
  Link,
  Microscope,
  PanelRight,
  Play,
  Plus,
  Save,
  Tag,
  Trash2,
  Upload,
  UserCheck,
  UserMinus,
  X,
} from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { useBulk } from '../../context/BulkContext.jsx'
import { useAutomation } from '../../context/AutomationContext.jsx'
import { useContextMenu } from '../../context/ContextMenuContext.jsx'
import { useFields } from '../../context/FieldsContext.jsx'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { typeOf } from '../../domain/fields.js'
import { usePageMenu } from '../menu/usePageMenu.js'
import {
  DEFAULT_SORT,
  PAGE_ROWS,
  allColumns,
  cleanColumns,
  fieldNames,
  neighbour,
  nextSort,
  readColumns,
  sortIncidents,
  writeColumns,
} from '../../domain/incidentList.js'
import { STATUSES, numberedName } from '../../domain/incidentName.js'
import { tagsInUse, withTag } from '../../domain/incidentTags.js'
import { tryParse } from '../../domain/query/parse.js'
import { filterPayload, filterView, isChanged } from '../../domain/savedFilters.js'
import { isTypingTarget } from '../../domain/search.js'
import { copyText } from '../../lib/download.js'
import { hasModalLayer } from '../../lib/layers.js'
import { api } from '../../services/api.js'
import { useQuerySchema } from '../../services/querySchema.js'
import { Badge, BulkBar, Button, EmptyState, Modal, useSelection } from '../ui/index.js'
import QueryInput from '../ui/QueryInput.jsx'
import ColumnsDialog from './ColumnsDialog.jsx'
import { ManageFiltersDialog, SaveFilterDialog } from './FilterDialogs.jsx'
import FilterMenu from './FilterMenu.jsx'
import IncidentTable from './IncidentTable.jsx'
import IncidentTags from '../incident/IncidentTags.jsx'
import QuickChips from './QuickChips.jsx'
import QuickView from './QuickView.jsx'
import { useSavedFilters } from './useSavedFilters.js'
import SearchBar from '../layout/SearchBar.jsx'

/*
 * ============================================================================
 * THE INCIDENT LIST — a page of its own, next to the rail
 * ============================================================================
 *
 * A table of every incident that takes the whole area, with above it the
 * query that filters it (the server reads it), the saved filters, the chips
 * that write a condition, and the choice of the columns. A click on a row
 * opens the quick view over the right side of the page; a double click opens
 * the incident. A click on a tag, in a row or in the quick view, adds it to
 * the query.
 *
 * The rows are the light list the incident context holds; the query is asked
 * of the server, which answers with the incidents it keeps, and with the
 * fields of the registry the chosen columns need.
 *
 * What is on screen (the query, the chosen filter, the order) is kept while
 * the browser tab lives, so coming back from an incident finds the list as it
 * was left. A reload starts again from the person's default filter.
 */

const SEVERITIES = ['critical', 'high', 'medium', 'low']
const TLPS = ['clear', 'green', 'amber', 'amber+strict', 'red']
const DIRECTIONS = [
  { value: 'in', label: 'In' },
  { value: 'out', label: 'Out' },
  { value: 'both', label: 'In-out' },
  { value: 'none', label: 'None (stop mirroring)' },
]
const SENDING = ['out', 'both']
// How many incidents one click exports, each to its own file.
const EXPORT_MAX = 25

/**
 * What the bar offers for the selected incidents. An action the account may not do is not in
 * the list at all. Every change goes through the dialog of the bulk actions, which says what it
 * would do before it does it.
 */
function incidentActions({
  picked,
  rows,
  query,
  me,
  assignees,
  types,
  canWrite,
  canAutomate,
  askBulk,
  onDone,
  exportIncident,
  showToast,
}) {
  if (picked.count === 0) return []
  const selected = picked.all ? rows : rows.filter((row) => picked.has(row.id))
  const ask = (action, title, more = {}) =>
    askBulk({
      list: 'incidents',
      action,
      title,
      selection: picked.body({ q: query }),
      onStarted: picked.reset,
      onDone,
      ...more,
    })
  const set = (title, label, name, options) =>
    ask('set', title, { form: { kind: 'choice', label, options, params: (value) => ({ changes: { [name]: value } }) } })
  const write = [
    { group: 'Triage' },
    {
      id: 'status',
      label: 'Set the status…',
      onSelect: () =>
        set(
          'Set the status',
          'Status',
          'status',
          STATUSES.filter((status) => status.value !== 'closed').map(({ value, label }) => ({ value, label })),
        ),
    },
    {
      id: 'close',
      label: 'Close…',
      onSelect: () => ask('set', 'Close the incidents', { form: { kind: 'close', rows: selected } }),
    },
    {
      id: 'severity',
      label: 'Set the severity…',
      onSelect: () =>
        set(
          'Set the severity',
          'Severity',
          'severity',
          SEVERITIES.map((value) => ({ value, label: value })),
        ),
    },
    {
      id: 'owner',
      label: 'Assign…',
      onSelect: () =>
        ask('set', 'Assign the incidents', {
          form: {
            kind: 'choice',
            label: 'Owner',
            options: [
              ...(me ? [{ value: me, label: `Me (${me})` }] : []),
              ...assignees.filter((name) => name !== me).map((name) => ({ value: name, label: name })),
              { value: '\u0000', label: 'Nobody (remove the owner)' },
            ],
            params: (value) => ({ changes: { owner: value === '\u0000' ? null : value } }),
          },
        }),
    },
    {
      id: 'type',
      label: 'Set the type…',
      onSelect: () =>
        set(
          'Set the type',
          'Type',
          'type',
          types.map((type) => ({ value: type.id, label: type.name })),
        ),
    },
    {
      id: 'tlp',
      label: 'Set the TLP…',
      onSelect: () =>
        set(
          'Set the TLP',
          'TLP',
          'tlp',
          TLPS.map((value) => ({ value, label: `TLP:${value.toUpperCase()}` })),
        ),
    },
    {
      id: 'tags',
      label: 'Change the tags…',
      onSelect: () => ask('tags', 'Change the tags', { form: { kind: 'tags' } }),
    },
    {
      id: 'field',
      label: 'Set another field…',
      onSelect: () => ask('set', 'Set a field', { form: { kind: 'field' } }),
    },
    { group: 'Evidence and mirroring' },
    {
      id: 'find',
      label: 'Find indicators now',
      onSelect: () => ask('find_indicators', 'Find indicators now', { params: {} }),
    },
    {
      id: 'mirror',
      label: 'Change mirroring…',
      onSelect: () =>
        ask('mirror', 'Change mirroring', {
          form: {
            kind: 'choice',
            label: 'Direction',
            // Out and In-out send to another system: as on one incident, only who may run playbooks.
            options: canAutomate ? DIRECTIONS : DIRECTIONS.filter((choice) => !SENDING.includes(choice.value)),
            params: (value) => ({ direction: value }),
          },
        }),
    },
  ]
  const exportAll = async () => {
    if (selected.length > EXPORT_MAX) {
      showToast({
        message: `An export is one file for each incident: ${EXPORT_MAX} at most at a time. Select fewer.`,
      })
      return
    }
    for (const row of selected) await exportIncident(row.id)
  }
  const copyLinks = async () => {
    const links = selected.map((row) => `${window.location.origin}/incident/${encodeURIComponent(row.id)}`)
    showToast({
      message: (await copyText(links.join('\n')))
        ? `${links.length} ${links.length === 1 ? 'link' : 'links'} copied.`
        : 'The browser refused to copy.',
    })
  }
  return [
    ...(canWrite ? write : []),
    ...(canAutomate
      ? [
          { group: 'Automation' },
          {
            id: 'playbook',
            label: 'Run a playbook on each…',
            onSelect: () =>
              ask('playbook', 'Run a playbook on each', {
                form: { kind: 'playbook', params: (value) => ({ playbook: value }) },
              }),
          },
        ]
      : []),
    { group: 'Take out' },
    { id: 'export', label: 'Export (JSON)', onSelect: exportAll },
    { id: 'links', label: 'Copy the links', onSelect: copyLinks },
    ...(canWrite ? [{ id: 'delete', label: 'Delete…', onSelect: () => ask('delete', 'Delete the incidents') }] : []),
  ]
}

// What each account had on screen, for the life of the browser tab: { [username]: view }.
const remembered = new Map()
const EMPTY_VIEW = { query: '', filterId: null, sort: DEFAULT_SORT, columns: null }

/**
 * @param {{
 *   onCreateIncident: () => void,             // opens the "New incident" modal owned by App
 *   onNewAnalysis: () => void,                // opens the "New analysis" dialog owned by App
 *   onOpenIncident: (id: string) => void,     // opens an incident in the main area
 *   onOpenReport: (id: string) => void,       // opens an incident and its report
 * }} props
 */
export default function IncidentsPage({ onCreateIncident, onNewAnalysis, onOpenIncident, onOpenReport }) {
  const {
    incidents,
    assignees,
    deleteIncident,
    exportIncident,
    importIncidentFromFile,
    setIncidentTriage,
    askClose,
    refreshIncidents,
    storageError,
    unsavedChanges,
  } = useIncidents()
  const { askBulk } = useBulk()
  const { currentUser, can } = useAuth()
  const { fields, types } = useFields()
  const { openMenu } = useContextMenu()
  const { showToast } = useToast()
  const { allowed: canAutomate, askRun } = useAutomation()
  const schema = useQuerySchema('incidents')
  const saved = useSavedFilters('incidents')
  const canWrite = can('write')
  const me = currentUser?.username ?? ''
  const pageRef = useRef(null)

  // ---- what is on screen: the query, the chosen filter, the order, the columns of a filter ----
  const [view, setViewState] = useState(() => remembered.get(me) ?? EMPTY_VIEW)
  const setView = useCallback(
    (change) =>
      setViewState((current) => ({ ...current, ...(typeof change === 'function' ? change(current) : change) })),
    [],
  )
  // Kept for the next time the page is opened, once the list has started (see the default filter below).
  useEffect(() => {
    if (remembered.has(me)) remembered.set(me, view)
  }, [me, view])
  // The columns the person chose for themselves (this browser); a filter may put others on screen.
  const [ownColumns, setOwnColumns] = useState(() => readColumns(localStorage))
  const columns = useMemo(() => allColumns(fields), [fields])
  const chosenKeys = useMemo(
    () => cleanColumns(view.columns ?? ownColumns, columns),
    [view.columns, ownColumns, columns],
  )
  const shownColumns = useMemo(
    () => chosenKeys.map((key) => columns.find((column) => column.key === key)).filter(Boolean),
    [chosenKeys, columns],
  )
  const chosen = saved.filters.find((filter) => filter.id === view.filterId) ?? null
  // The tags the incidents carry, the most used first: what the Tag chip lists and tag: completes.
  const inUse = useMemo(() => tagsInUse(incidents), [incidents])
  const offered = useMemo(() => ({ labels: inUse.map((item) => item.tag) }), [inUse])
  const filterByTag = (tag) => setView((current) => ({ query: withTag(current.query, tag, schema) }))
  const changed = isChanged(chosen, { query: view.query, sort: view.sort, columns: chosenKeys })

  // The list opens with the person's default filter: once for each account, when the filters are read.
  useEffect(() => {
    if (!saved.ready || remembered.has(me)) return
    const first = saved.filters.find((filter) => filter.id === saved.defaultId)
    // With no default the list starts as it is: what was typed while the filters were read stays.
    const start = first ? { ...filterView(first), filterId: first.id } : view
    remembered.set(me, start)
    if (first) setViewState(start)
  }, [saved.ready, saved.filters, saved.defaultId, me, view])
  // A filter that was deleted, or is no longer shared, is no longer the chosen one.
  useEffect(() => {
    if (saved.ready && view.filterId && !chosen) setView({ filterId: null })
  }, [saved.ready, view.filterId, chosen, setView])

  const choose = (filter) => setView(filter ? { ...filterView(filter), filterId: filter.id } : EMPTY_VIEW)
  const setColumns = (keys) => {
    // The person's own choice, kept in this browser, and what the screen shows from now on.
    writeColumns(localStorage, keys)
    setOwnColumns(keys)
    setView({ columns: keys })
  }

  // ---- the incidents the query keeps, and the fields the columns need: asked of the server ----
  // `query`: what the rows on screen are the answer to (while a new query is asked, the old one).
  const [match, setMatch] = useState({ ids: null, fields: null, error: null, query: '' })
  const wanted = fieldNames(chosenKeys, columns).join(',')
  // Asked again when the list changes or a change reaches the server, so an edit shows in the filter.
  const stamp = `${incidents.length}:${incidents.reduce((latest, row) => (row.updatedAt > latest ? row.updatedAt : latest), '')}:${unsavedChanges}`
  useEffect(() => {
    const text = view.query.trim()
    if (!text && !wanted) {
      setMatch({ ids: null, fields: null, error: null, query: '' })
      return undefined
    }
    // What cannot be read is said by the input; the list stays as it was.
    if (tryParse(text).error) return undefined
    let cancelled = false
    const timer = setTimeout(() => {
      const asked = [
        'view=summary',
        ...(text ? [`q=${encodeURIComponent(text)}`] : []),
        ...(wanted ? [`fields=${encodeURIComponent(wanted)}`] : []),
      ]
      api
        .get(`/incidents?${asked.join('&')}`)
        .then((answer) => {
          if (cancelled) return
          const found = answer?.incidents ?? []
          setMatch({
            ids: text ? new Set(found.map((row) => row.id)) : null,
            fields: wanted ? new Map(found.map((row) => [row.id, row.fields ?? {}])) : null,
            error: null,
            query: text,
          })
        })
        .catch((failure) => {
          if (!cancelled) setMatch((current) => ({ ...current, error: failure.query ?? { message: failure.message } }))
        })
    }, 250)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [view.query, wanted, stamp])

  const rows = useMemo(() => {
    const kept = incidents
      .filter((row) => !match.ids || match.ids.has(row.id))
      .map((row) => (match.fields ? { ...row, fields: match.fields.get(row.id) ?? {} } : row))
    return sortIncidents(kept, view.sort, columns, { types })
  }, [incidents, match.ids, match.fields, view.sort, columns, types])
  const [limit, setLimit] = useState(PAGE_ROWS)
  const drawn = useMemo(() => rows.slice(0, limit), [rows, limit])

  // ---- the selection, and what is done to it ----
  const drawnIds = useMemo(() => drawn.map((row) => row.id), [drawn])
  // A bulk action names the query the rows on screen answer, never one still being asked.
  const query = match.query
  const keptIds = useMemo(() => new Set(rows.map((row) => row.id)), [rows])
  const picked = useSelection({ filter: query, pageIds: drawnIds, total: rows.length, known: keptIds })
  const bulkActions = incidentActions({
    picked,
    rows,
    query,
    me,
    assignees,
    types,
    canWrite,
    canAutomate,
    askBulk,
    onDone: refreshIncidents,
    exportIncident,
    showToast,
  })

  // ---- the quick view: the row that is shown ----
  const [shownId, setShownId] = useState(null)
  const shown = shownId ? (rows.find((row) => row.id === shownId) ?? null) : null
  // The keys of the quick view, wherever the focus is on the page: Escape closes it, the arrows change row.
  useEffect(() => {
    if (!shown) return undefined
    const ids = drawn.map((row) => row.id)
    const onKeyDown = (event) => {
      // A dialog or a menu over the page has the keys; a key a control already took is not taken twice.
      if (event.defaultPrevented || hasModalLayer() || event.altKey || event.ctrlKey || event.metaKey) return
      if (event.key === 'Escape') {
        setShownId(null)
        return
      }
      if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return
      if (isTypingTarget(event.target) || event.target.closest?.('[role="menu"], [role="separator"]')) return
      const next = neighbour(ids, shown.id, event.key === 'ArrowDown' ? 1 : -1)
      event.preventDefault()
      if (next === null || next === shown.id) return
      setShownId(next)
      pageRef.current?.querySelector(`tr[data-row="${CSS.escape(next)}"]`)?.scrollIntoView({ block: 'nearest' })
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [shown, drawn])

  // ---- what is done to a row: its menu, export, delete; and the import ----
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [exportingId, setExportingId] = useState(null)
  const [importError, setImportError] = useState(null)
  const [importing, setImporting] = useState(false)
  const fileInputRef = useRef(null)
  const [dialog, setDialog] = useState(null) // 'save' | 'manage' | 'columns'
  // The incident whose tags are changed from the menu of its row (its id: the row is read as it is now).
  const [taggingId, setTaggingId] = useState(null)
  const tagging = taggingId ? (incidents.find((row) => row.id === taggingId) ?? null) : null

  const exportRow = async (row) => {
    setExportingId(row.id)
    try {
      await exportIncident(row.id)
    } finally {
      setExportingId(null)
    }
  }
  const handleImportFile = async (event) => {
    const file = event.target.files?.[0]
    // Reset the input so the same file can be imported again right after.
    event.target.value = ''
    if (!file) return
    setImporting(true)
    setImportError(null)
    try {
      await importIncidentFromFile(file)
    } catch (error) {
      setImportError(error.message)
    } finally {
      setImporting(false)
    }
  }
  const rowMenu = (event, row) =>
    openMenu(event, {
      title: row.name,
      items: [
        { label: 'Open', icon: FolderOpen, onSelect: () => onOpenIncident(row.id) },
        { label: 'Quick view', icon: PanelRight, onSelect: () => setShownId(row.id) },
        { label: 'Incident report…', icon: FileText, onSelect: () => onOpenReport(row.id) },
        { label: 'Export (JSON)', icon: Download, onSelect: () => exportIncident(row.id) },
        {
          label: 'Copy link',
          icon: Link,
          onSelect: async () => {
            const url = `${window.location.origin}/incident/${encodeURIComponent(row.id)}`
            showToast({ message: (await copyText(url)) ? 'Link copied.' : 'The browser refused to copy.' })
          },
        },
        ...(canAutomate
          ? [
              {
                label: 'Run a playbook…',
                icon: Play,
                onSelect: () => askRun({ incidentId: row.id, incidentName: row.name }),
              },
            ]
          : []),
        ...(canWrite
          ? [
              'separator',
              { label: 'Add a tag…', icon: Tag, onSelect: () => setTaggingId(row.id) },
              ...STATUSES.filter((status) => status.value !== row.status).map((status) => ({
                label: `Mark as ${status.label}`,
                icon: CircleDot,
                // Closing asks for a reason, and for what the type wants filled first.
                onSelect: () =>
                  status.value === 'closed' ? askClose(row.id) : setIncidentTriage(row.id, { status: status.value }),
              })),
              ...(me && row.assignee.toLowerCase() !== me.toLowerCase()
                ? [
                    {
                      label: 'Assign to me',
                      icon: UserCheck,
                      onSelect: () => setIncidentTriage(row.id, { assignee: me }),
                    },
                  ]
                : []),
              ...(row.assignee
                ? [
                    {
                      label: `Remove the assignee (${row.assignee})`,
                      icon: UserMinus,
                      onSelect: () => setIncidentTriage(row.id, { assignee: '' }),
                    },
                  ]
                : []),
              'separator',
              { label: 'Delete…', icon: Trash2, onSelect: () => setDeleteTarget(row) },
            ]
          : []),
      ],
    })

  // What the page itself offers, in every right-click menu opened on it.
  const pageMenu = usePageMenu(() => [
    canWrite && { label: 'New incident…', icon: Plus, onSelect: onCreateIncident },
    { label: 'Columns…', icon: Columns3, onSelect: () => setDialog('columns') },
  ])

  const saveFilter = async ({ id, name }) => {
    const body = filterPayload({ name, query: view.query, sort: view.sort, columns: chosenKeys })
    const kept = id ? await saved.update(id, body) : await saved.create(body)
    setView({ ...filterView(kept), filterId: kept.id })
    showToast({ message: `The filter "${kept.name}" is saved.` })
  }

  return (
    <section
      ref={pageRef}
      aria-label="Incidents"
      className="relative flex min-w-0 flex-1 flex-col overflow-hidden bg-canvas"
      onContextMenu={pageMenu}
    >
      {/* ----- Title, count, what is made here ----- */}
      <header className="@container flex shrink-0 items-center gap-3 px-6 pb-2 pt-4">
        <h1 className="flex-1 basis-0 text-lg font-semibold text-fg">Incidents</h1>
        <SearchBar />
        <div className="flex flex-1 basis-0 items-center justify-end gap-3">
          <p role="status" aria-label="Incidents listed" className="whitespace-nowrap font-mono text-xs text-fg-muted">
            {rows.length === incidents.length
              ? `${incidents.length} ${incidents.length === 1 ? 'incident' : 'incidents'}`
              : `${rows.length} of ${incidents.length}`}
          </p>
          <Button variant="secondary" size="sm" icon={Columns3} onClick={() => setDialog('columns')}>
            Columns…
          </Button>
          {!canWrite && (
            <span
              className="flex h-8 items-center border border-line px-2.5 font-mono text-xs text-fg-muted"
              title="Your roles let you read, not change: ask an admin for the Analyst role to work on incidents."
            >
              read-only
            </span>
          )}
          {canWrite && (
            <>
              <Button
                waiting={importing}
                variant="secondary"
                size="sm"
                icon={Upload}
                disabled={importing}
                onClick={() => fileInputRef.current?.click()}
              >
                {importing ? 'Importing…' : 'Import incident'}
              </Button>
              <input ref={fileInputRef} type="file" accept=".json" hidden onChange={handleImportFile} />
              <Button size="sm" icon={Plus} onClick={onCreateIncident}>
                New incident
              </Button>
            </>
          )}
        </div>
      </header>

      {/* ----- The saved filters, the query, the chips that write into it ----- */}
      <div className="flex shrink-0 flex-col gap-2 border-b border-line px-6 pb-3">
        <div className="flex items-start gap-2">
          <FilterMenu
            filters={saved.filters}
            defaultId={saved.defaultId}
            chosen={chosen}
            onChoose={choose}
            onDefault={(id) => saved.setDefault(id).catch((failure) => showToast({ message: failure.message }))}
            onManage={() => setDialog('manage')}
          />
          <QueryInput
            entity="incidents"
            label="Filter incidents"
            placeholder="status:open severity:>=high…"
            value={view.query}
            onChange={(query) => setView({ query })}
            error={match.error}
            values={offered}
            className="min-w-0 flex-1"
          />
          <Button variant="secondary" size="sm" icon={Save} onClick={() => setDialog('save')}>
            Save the filter…
          </Button>
        </div>
        <QuickChips
          query={view.query}
          onChange={(query) => setView({ query })}
          schema={schema}
          types={types}
          assignees={assignees}
          me={me}
          tags={inUse}
        >
          {changed && (
            <>
              <Badge color="amber">changed since saved</Badge>
              <Button variant="secondary" size="xs" onClick={() => choose(chosen)}>
                Back to the saved one
              </Button>
            </>
          )}
        </QuickChips>
      </div>

      {(storageError || importError) && (
        <div
          role="alert"
          className="flex shrink-0 items-center gap-2 border-b border-high-line bg-high-soft px-6 py-2 text-sm text-high-fg"
        >
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span className="min-w-0 flex-1">{importError ?? storageError}</span>
          {importError && (
            <button
              type="button"
              aria-label="Dismiss error message"
              onClick={() => setImportError(null)}
              className="p-0.5 hover:bg-high-line/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      )}

      <BulkBar picked={picked} noun="incidents" actions={bulkActions} className="mx-6 mt-2 shrink-0" />

      {/* ----- The table (its own scroll, in both directions) ----- */}
      <div className="min-h-0 flex-1 overflow-auto">
        {incidents.length === 0 ? (
          <div className="flex h-full items-center justify-center p-6">
            <EmptyState
              skull
              title="No incidents yet"
              message={
                canWrite
                  ? 'Create an incident to work a case, or analyse a file or an e-mail on its own. You can also drop a file anywhere.'
                  : 'An incident appears here when someone creates one, or when a connector brings one in.'
              }
              action={
                canWrite && (
                  <div className="flex flex-wrap justify-center gap-2">
                    <Button icon={Plus} onClick={onCreateIncident}>
                      New incident
                    </Button>
                    <Button variant="secondary" icon={Microscope} onClick={onNewAnalysis}>
                      New analysis
                    </Button>
                  </div>
                )
              }
            />
          </div>
        ) : (
          <>
            <IncidentTable
              rows={drawn}
              columns={shownColumns}
              types={types}
              sort={view.sort}
              onSort={(column) => setView((current) => ({ sort: nextSort(current.sort, column) }))}
              shownId={shown?.id ?? null}
              onShow={setShownId}
              onOpen={onOpenIncident}
              onMove={(id) => shown && setShownId(id)}
              onMenu={rowMenu}
              onTag={filterByTag}
              canWrite={canWrite}
              exportingId={exportingId}
              onExport={exportRow}
              onDelete={setDeleteTarget}
              picked={picked}
            />
            {rows.length === 0 && (
              <EmptyState
                skull
                className="mx-6 my-6"
                title="No incident matches"
                message="No incident matches the filter. Change the query, or take the filter off."
              />
            )}
            {rows.length > drawn.length && (
              <p className="flex items-center gap-3 px-6 py-3 text-xs text-fg-muted">
                {drawn.length} of {rows.length} shown
                <Button variant="secondary" size="xs" onClick={() => setLimit((current) => current + PAGE_ROWS)}>
                  Show {Math.min(PAGE_ROWS, rows.length - drawn.length)} more
                </Button>
              </p>
            )}
          </>
        )}
      </div>

      {shown && (
        <QuickView
          row={shown}
          type={typeOf(types, shown)}
          onClose={() => setShownId(null)}
          onOpen={onOpenIncident}
          onTag={filterByTag}
        />
      )}

      {/* ----- The tags of a row, from its menu ----- */}
      {tagging && (
        <Modal
          open
          onClose={() => setTaggingId(null)}
          title={`Tags of ${numberedName(tagging)}`}
          footer={<Button onClick={() => setTaggingId(null)}>Done</Button>}
        >
          <div className="flex min-h-48 flex-col gap-3">
            <IncidentTags incidentId={tagging.id} tags={tagging.tags} startOpen />
            <p className="text-xs text-fg-muted">
              Enter adds what is typed, Backspace in the empty input takes the last tag off. Each change is saved at
              once.
            </p>
          </div>
        </Modal>
      )}

      {dialog === 'columns' && (
        <ColumnsDialog
          columns={columns}
          chosen={chosenKeys}
          onChange={setColumns}
          onReset={() => {
            writeColumns(localStorage, null)
            setOwnColumns(null)
            setView({ columns: null })
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog === 'save' && (
        <SaveFilterDialog
          query={view.query}
          chosen={chosen}
          filters={saved.filters}
          onSave={saveFilter}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog === 'manage' && (
        <ManageFiltersDialog
          filters={saved.filters}
          defaultId={saved.defaultId}
          canShare={can('admin')}
          onRename={(id, name) => saved.update(id, { name })}
          onShare={saved.share}
          onDelete={saved.remove}
          onClose={() => setDialog(null)}
        />
      )}

      {/* ----- Delete confirmation ----- */}
      <Modal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        title="Delete incident"
        footer={
          <>
            <Button variant="secondary" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              icon={Trash2}
              onClick={() => {
                // The row leaves the list once the server has deleted it; a failure is reported.
                deleteIncident(deleteTarget.id)
                setDeleteTarget(null)
              }}
            >
              Delete permanently
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="text-sm text-fg">
            You are about to delete the incident <strong className="font-mono">«{deleteTarget?.name}»</strong>.
          </p>
          <p className="flex items-start gap-2 border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            This action is irreversible: every imported artifact and analysis in this incident will be lost. Export the
            incident first if you want to keep a copy.
          </p>
        </div>
      </Modal>
    </section>
  )
}
