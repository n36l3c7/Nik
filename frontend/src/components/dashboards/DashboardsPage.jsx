import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Copy,
  Download,
  FileText,
  FolderOpen,
  House,
  Pencil,
  Plus,
  RefreshCw,
  Share2,
  Trash2,
  Upload,
  X,
} from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { api, postForBlob } from '../../services/api.js'
import {
  ENTITIES,
  LANDING_KEY,
  RANGES,
  REFRESH,
  TYPES,
  arrange,
  compactGrid,
  widgetQuery,
  dashboardsPath,
  landingDashboard,
  newWidget,
  rangeLabel,
  sharingText,
} from '../../domain/dashboards.js'
import { ROLES } from '../../domain/permissions.js'
import { generateId } from '../../lib/id.js'
import { copyText, saveBlob } from '../../lib/download.js'
import { Badge, Button, EmptyState, Modal, Select } from '../ui/index.js'
import QueryInput from '../ui/QueryInput.jsx'
import Grid from './Grid.jsx'
import Widget from './Widget.jsx'
import WidgetEditor from './WidgetEditor.jsx'
import ResizeHandle, { useResizablePane } from '../ui/ResizeHandle.jsx'
import { useObjectMenu } from '../menu/useObjectMenu.js'

/*
 * ============================================================================
 * DASHBOARDS — widgets on a grid, each a question asked of what Nik holds
 * ============================================================================
 *
 * A page next to the rail, like My tasks: the dashboards on the left (Nik's,
 * yours, those shared with you), the one that is open on the right with its
 * time range. Its address is /dashboards/<id>. Editing happens on a copy of
 * the dashboard held here, saved or dropped as a whole.
 */

const FIELD =
  'h-8 min-w-0 border border-line bg-canvas px-2 text-sm text-fg ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/** The objects behind a value: their query, and the first of them. */
function DrillDialog({ what, onClose, onOpenIncident }) {
  const [found, setFound] = useState(null)
  const [error, setError] = useState(null)
  useEffect(() => {
    let cancelled = false
    api.post('/query', { entity: what.entity, query: what.query, limit: 50 }).then(
      (data) => !cancelled && setFound(data),
      (failure) => !cancelled && setError(failure.message),
    )
    return () => {
      cancelled = true
    }
  }, [what])
  const items = found?.items ?? []
  const columns = items.length
    ? Object.keys(items[0])
        .filter((name) => !['id', 'ref'].includes(name) && typeof items[0][name] !== 'object')
        .slice(0, 6)
    : []
  const cell = (value) => {
    if (typeof value === 'boolean') return value ? 'yes' : 'no'
    if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(value)) return value.slice(0, 16).replace('T', ' ')
    return value == null || value === '' ? '—' : String(value)
  }
  return (
    <Modal open onClose={onClose} title={what.title} maxWidth="max-w-4xl">
      <div className="mb-3 flex items-start gap-2">
        <code className="min-w-0 flex-1 break-all border border-line bg-canvas px-2 py-1.5 font-mono text-xs text-fg">
          {what.query || '(everything)'}
        </code>
        <Button variant="secondary" size="xs" icon={Copy} onClick={() => copyText(what.query)}>
          Copy the query
        </Button>
      </div>
      {error && <p className="text-sm text-high">{error}</p>}
      {!found && !error && (
        <p role="status" className="text-sm text-fg-muted">
          Loading…
        </p>
      )}
      {found && (
        <>
          <p className="mb-2 text-xs text-fg-muted">
            {found.total.toLocaleString('en-US')} {found.total === 1 ? 'object' : 'objects'}
            {found.total > items.length ? `, the first ${items.length} shown` : ''}
          </p>
          <div className="overflow-x-auto border border-line">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-line text-fg-muted">
                  {columns.map((name) => (
                    <th key={name} className="px-2 py-1.5 font-medium">
                      {name}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {items.map((item, index) => (
                  <tr key={item.id ?? index} className="border-b border-line-soft last:border-0">
                    {columns.map((name, at) => (
                      <td key={name} className="max-w-[16rem] truncate px-2 py-1.5 text-fg">
                        {at === 0 && what.entity === 'incidents' ? (
                          <button
                            type="button"
                            onClick={() => onOpenIncident(item.id)}
                            className="text-left text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                          >
                            {cell(item[name])}
                          </button>
                        ) : (
                          cell(item[name])
                        )}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Modal>
  )
}

/** Who else sees a dashboard. */
function ShareDialog({ board, onSaved, onClose }) {
  const [everyone, setEveryone] = useState(Boolean(board.sharedWith?.everyone))
  const [roles, setRoles] = useState(board.sharedWith?.roles ?? [])
  const [users, setUsers] = useState((board.sharedWith?.users ?? []).join(', '))
  const [error, setError] = useState(null)
  const save = () => {
    const body = {
      everyone,
      roles: everyone ? [] : roles,
      users: everyone ? [] : users.split(',').map((name) => name.trim()).filter(Boolean),
    } // prettier-ignore
    api.put(`/dashboards/${board.id}/sharing`, body).then(onSaved, (failure) => setError(failure.message))
  }
  return (
    <Modal
      open
      onClose={onClose}
      title={`Share "${board.name}"`}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={save}>Save</Button>
        </>
      }
    >
      <div className="space-y-4 text-sm">
        <p className="text-fg-muted">
          Whoever sees a dashboard sees in each widget only what their own roles let them read: sharing shows the
          questions, never more of the answers.
        </p>
        <label className="flex items-center gap-2 text-fg">
          <input
            type="checkbox"
            checked={everyone}
            onChange={(event) => setEveryone(event.target.checked)}
            className="h-4 w-4 accent-[var(--color-accent)]"
          />
          Everyone
        </label>
        <fieldset disabled={everyone} className="space-y-1.5 disabled:opacity-50">
          <legend className="mb-1 text-xs font-medium text-fg-muted">Whoever holds one of these roles</legend>
          <div className="flex flex-wrap gap-x-4 gap-y-1">
            {ROLES.map((role) => (
              <label key={role.id} className="flex items-center gap-2 text-fg">
                <input
                  type="checkbox"
                  checked={roles.includes(role.id)}
                  onChange={(event) =>
                    setRoles((old) => (event.target.checked ? [...old, role.id] : old.filter((id) => id !== role.id)))
                  }
                  className="h-4 w-4 accent-[var(--color-accent)]"
                />
                {role.label}
              </label>
            ))}
          </div>
        </fieldset>
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-fg-muted">These accounts (usernames, with commas)</span>
          <input
            type="text"
            value={users}
            disabled={everyone}
            onChange={(event) => setUsers(event.target.value)}
            className={`${FIELD} w-full disabled:opacity-50`}
          />
        </label>
        {error && <p className="text-high">{error}</p>}
      </div>
    </Modal>
  )
}

/**
 * @param {{
 *   dashboardId: string | null,
 *   onSelect: (id: string | null, options?: { replace?: boolean }) => void,
 *   onClose: () => void,
 *   onOpenIncident: (id: string) => void,
 * }} props
 */
export default function DashboardsPage({ dashboardId, onSelect, onClose, onOpenIncident }) {
  const { can } = useAuth()
  const ref = useRef(null)
  const fileRef = useRef(null)
  const editNext = useRef(null) // a dashboard just made opens ready to be edited
  const [boards, setBoards] = useState(null)
  const [board, setBoard] = useState(null)
  const [draft, setDraft] = useState(null) // the dashboard while it is edited
  const [range, setRange] = useState('30d')
  const [tick, setTick] = useState(0)
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)
  const [editingWidget, setEditingWidget] = useState(null)
  const [drill, setDrill] = useState(null)
  const [sharing, setSharing] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [landing, setLanding] = useState(landingDashboard)
  const [adding, setAdding] = useState(false)
  const menu = useObjectMenu()
  const listPane = useResizablePane('dashboards.list', { initial: 224, min: 180, max: 420 })

  useEffect(() => {
    ref.current?.focus()
  }, [])

  const reload = useCallback(
    () =>
      api.get('/dashboards').then(
        (found) => setBoards(found.dashboards),
        (failure) => setError(failure.message),
      ),
    [],
  )
  useEffect(() => {
    reload()
  }, [reload])

  // With the page alone open: the dashboard chosen for sign-in, or the first.
  useEffect(() => {
    if (dashboardId || !boards?.length) return
    const wanted = boards.find((item) => item.id === landing) ?? boards[0]
    onSelect(wanted.id, { replace: true })
  }, [dashboardId, boards, landing, onSelect])

  useEffect(() => {
    if (!dashboardId) return undefined
    let cancelled = false
    setDraft(null)
    api.get(`/dashboards/${encodeURIComponent(dashboardId)}`).then(
      (found) => {
        if (cancelled) return
        setBoard(found)
        setRange(found.timeRange)
        setError(null)
        if (editNext.current === found.id) setDraft(found)
        editNext.current = null
      },
      (failure) => {
        if (cancelled) return
        setBoard(null)
        setError(failure.status === 404 ? 'This dashboard does not exist, or is not shared with you.' : failure.message)
      },
    )
    return () => {
      cancelled = true
    }
  }, [dashboardId])

  // The dashboard asks again by itself when it says so, while nobody edits it.
  const refreshSeconds = draft ? 0 : (board?.refreshSeconds ?? 0)
  useEffect(() => {
    if (!refreshSeconds) return undefined
    const timer = setInterval(() => setTick((old) => old + 1), refreshSeconds * 1000)
    return () => clearInterval(timer)
  }, [refreshSeconds])

  const shown = draft ?? board
  const editing = Boolean(draft)
  const setWidgets = (widgets) => setDraft((old) => ({ ...old, widgets }))

  const create = () =>
    api.post('/dashboards', { name: 'New dashboard', widgets: [] }).then(
      (made) => {
        reload()
        editNext.current = made.id
        onSelect(made.id)
      },
      (failure) => setError(failure.message),
    )
  const save = () => {
    setSaving(true)
    const body = {
      name: draft.name,
      description: draft.description,
      widgets: draft.widgets,
      timeRange: draft.timeRange,
      refreshSeconds: draft.refreshSeconds,
      filter: draft.filter ?? '',
      filterEntity: draft.filterEntity ?? 'incidents',
    }
    api
      .put(`/dashboards/${draft.id}`, body)
      .then(
        (saved) => {
          setBoard(saved)
          setRange(saved.timeRange)
          setDraft(null)
          setError(null)
          reload()
        },
        (failure) => setError(failure.message),
      )
      .finally(() => setSaving(false))
  }
  const duplicate = () =>
    api.post(`/dashboards/${board.id}/duplicate`).then(
      (copy) => {
        reload()
        onSelect(copy.id)
      },
      (failure) => setError(failure.message),
    )
  const remove = () =>
    api.del(`/dashboards/${board.id}`).then(
      () => {
        setRemoving(false)
        setBoard(null)
        reload()
        onSelect(null, { replace: true })
      },
      (failure) => setError(failure.message),
    )
  const exportFile = () =>
    api.get(`/dashboards/${board.id}/export`).then(
      (file) => {
        const name = board.name.replace(/[^\w.-]+/g, '-').toLowerCase() || 'dashboard'
        saveBlob(new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' }), `${name}.dashboard.json`)
      },
      (failure) => setError(failure.message),
    )
  const [reporting, setReporting] = useState(false)
  const report = () => {
    setReporting(true)
    postForBlob(`/dashboards/${board.id}/report`, { format: 'pdf', timeRange: range })
      .then(
        (blob) => {
          const name = board.name.replace(/[^\w.-]+/g, '-').toLowerCase() || 'dashboard'
          saveBlob(blob, `${name}-dashboard.pdf`)
        },
        (failure) => setError(failure.message),
      )
      .finally(() => setReporting(false))
  }
  const importFile = async (event) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    try {
      const made = await api.post('/dashboards/import', JSON.parse(await file.text()))
      reload()
      onSelect(made.id)
    } catch (failure) {
      setError(failure instanceof SyntaxError ? 'This file is not a dashboard exported from Nik.' : failure.message)
    }
  }
  const toggleLanding = () => {
    const next = landing === board.id ? null : board.id
    setLanding(next)
    try {
      if (next) localStorage.setItem(LANDING_KEY, next)
      else localStorage.removeItem(LANDING_KEY)
    } catch {
      // Without storage the choice lasts as long as the page.
    }
  }
  const addWidget = (type) => {
    const widget = newWidget(type, generateId())
    setWidgets(compactGrid([...draft.widgets, widget]))
    setAdding(false)
    setEditingWidget(widget)
  }

  return (
    <section
      ref={ref}
      aria-label="Dashboards"
      tabIndex={-1}
      className="flex min-w-0 flex-1 flex-col bg-canvas outline-none"
    >
      <header className="flex h-14 shrink-0 items-center justify-between gap-3 border-b border-line bg-panel px-6">
        <h1 className="text-sm font-semibold text-fg">Dashboards</h1>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close dashboards"
          className="p-1.5 text-fg-muted hover:bg-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>
      </header>

      <div className="flex min-h-0 flex-1">
        <nav
          aria-label="Your dashboards"
          style={listPane.style}
          className="flex w-[var(--pane-w)] shrink-0 flex-col border-r border-line bg-panel"
        >
          <ul className="min-h-0 flex-1 overflow-y-auto py-2">
            {(boards ?? []).map((item) => (
              <li
                key={item.id}
                onContextMenu={(event) =>
                  menu(event, {
                    title: item.name,
                    actions: [
                      !(editing && item.id !== dashboardId) && {
                        label: 'Open',
                        icon: FolderOpen,
                        onSelect: () => onSelect(item.id),
                      },
                    ],
                    link: dashboardsPath(item.id),
                    copy: [{ label: 'Copy the name', text: item.name }],
                  })
                }
              >
                <button
                  type="button"
                  aria-current={item.id === dashboardId ? 'page' : undefined}
                  disabled={editing && item.id !== dashboardId}
                  onClick={() => onSelect(item.id)}
                  className={[
                    'flex w-full items-center gap-2 px-4 py-2 text-left text-sm disabled:opacity-50',
                    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent',
                    item.id === dashboardId ? 'bg-raised text-fg' : 'text-fg-muted hover:bg-raised hover:text-fg',
                  ].join(' ')}
                >
                  <span className="min-w-0 flex-1 truncate">{item.name}</span>
                  {item.builtin ? (
                    <Badge color="slate">Nik</Badge>
                  ) : item.shared ? (
                    <Badge color="cyan">shared</Badge>
                  ) : null}
                </button>
              </li>
            ))}
            {boards?.length === 0 && <li className="px-4 py-2 text-sm text-fg-muted">No dashboard yet.</li>}
          </ul>
          <div className="flex shrink-0 gap-2 border-t border-line p-3">
            <Button size="xs" icon={Plus} onClick={create} disabled={editing}>
              New
            </Button>
            <Button
              size="xs"
              variant="secondary"
              icon={Upload}
              onClick={() => fileRef.current?.click()}
              disabled={editing}
            >
              Import
            </Button>
            <input
              ref={fileRef}
              type="file"
              accept=".json,application/json"
              onChange={importFile}
              className="hidden"
              aria-label="A dashboard file"
            />
          </div>
        </nav>
        <ResizeHandle {...listPane.handle} label="Resize the list of dashboards" className="" />

        <div className="@container flex min-w-0 flex-1 flex-col overflow-y-auto">
          {error && (
            <p role="alert" className="border-b border-high-line bg-high-soft px-6 py-2 text-sm text-high-fg">
              {error}
            </p>
          )}
          {!shown && !error && boards?.length === 0 && (
            <EmptyState
              title="No dashboard yet"
              message="A dashboard is a set of widgets, each a question asked of what Nik holds: how many incidents are open, how long they take to close, which playbooks fail."
            />
          )}
          {shown && (
            <>
              <div className="flex flex-wrap items-center gap-2 border-b border-line px-6 py-3">
                {editing ? (
                  <input
                    type="text"
                    aria-label="The name of the dashboard"
                    maxLength={120}
                    value={draft.name}
                    onChange={(event) => setDraft((old) => ({ ...old, name: event.target.value }))}
                    className={`${FIELD} w-64 font-semibold`}
                  />
                ) : (
                  <div className="min-w-0">
                    <h2 className="truncate text-base font-semibold text-fg">{shown.name}</h2>
                    <p className="truncate text-xs text-fg-muted">
                      {sharingText(shown)}
                      {shown.description ? ` · ${shown.description}` : ''}
                    </p>
                  </div>
                )}
                <span className="flex-1" />
                {editing ? (
                  <>
                    <Button size="sm" variant="secondary" icon={Plus} onClick={() => setAdding(true)}>
                      Add a widget
                    </Button>
                    <Button size="sm" variant="secondary" onClick={() => setDraft(null)} disabled={saving}>
                      Cancel
                    </Button>
                    <Button size="sm" onClick={save} disabled={saving || !draft.name.trim()}>
                      {saving ? 'Saving…' : 'Save'}
                    </Button>
                  </>
                ) : (
                  <>
                    <Select
                      label="Time range"
                      value={range}
                      onChange={setRange}
                      options={[
                        ...RANGES.map((item) => ({ value: item.id, label: item.label })),
                        ...(RANGES.some((item) => item.id === range)
                          ? []
                          : [{ value: range, label: rangeLabel(range) }]),
                      ]}
                    />
                    <Button
                      size="sm"
                      variant="ghost"
                      icon={RefreshCw}
                      onClick={() => setTick((old) => old + 1)}
                      aria-label="Refresh"
                      title="Refresh"
                    />
                    <Button
                      size="sm"
                      variant="ghost"
                      icon={House}
                      aria-pressed={landing === shown.id}
                      onClick={toggleLanding}
                      aria-label={
                        landing === shown.id
                          ? 'Do not open this dashboard at sign-in'
                          : 'Open this dashboard at sign-in'
                      }
                      title={
                        landing === shown.id ? 'Opens at sign-in: click to stop' : 'Open this dashboard at sign-in'
                      }
                      className={landing === shown.id ? 'text-accent' : ''}
                    />
                    <Button
                      size="sm"
                      variant="ghost"
                      icon={Copy}
                      onClick={duplicate}
                      aria-label="Duplicate"
                      title="Duplicate: a copy of your own"
                    />
                    <Button
                      size="sm"
                      variant="ghost"
                      icon={Download}
                      onClick={exportFile}
                      aria-label="Export"
                      title="Export as a file"
                    />
                    <Button
                      size="sm"
                      variant="ghost"
                      icon={FileText}
                      onClick={report}
                      disabled={reporting}
                      aria-label="Report"
                      title="A PDF of this dashboard, with what you see in it"
                    />
                    {shown.canShare && (shown.canEdit || can('dashboards.share')) && (
                      <Button
                        size="sm"
                        variant="ghost"
                        icon={Share2}
                        onClick={() => setSharing(true)}
                        aria-label="Share"
                        title="Share"
                      />
                    )}
                    {shown.canEdit && (
                      <>
                        <Button
                          size="sm"
                          variant="ghost"
                          icon={Trash2}
                          onClick={() => setRemoving(true)}
                          aria-label="Delete"
                          title="Delete"
                        />
                        <Button size="sm" variant="secondary" icon={Pencil} onClick={() => setDraft(board)}>
                          Edit
                        </Button>
                      </>
                    )}
                  </>
                )}
              </div>

              {editing && (
                <div className="grid gap-3 border-b border-line bg-panel px-6 py-3 @3xl:grid-cols-[minmax(0,1fr)_auto_auto]">
                  <div className="min-w-0">
                    <span className="mb-1 block text-xs font-medium text-fg-muted">
                      A filter for every widget of{' '}
                      <select
                        aria-label="The entity the filter is written for"
                        value={draft.filterEntity ?? 'incidents'}
                        onChange={(event) =>
                          setDraft((old) => ({ ...old, filterEntity: event.target.value, filter: '' }))
                        }
                        className="border border-line bg-canvas px-1 py-0.5 text-xs text-fg"
                      >
                        {ENTITIES.map((entity) => (
                          <option key={entity.id} value={entity.id}>
                            {entity.label.toLowerCase()}
                          </option>
                        ))}
                      </select>
                    </span>
                    <QueryInput
                      entity={draft.filterEntity ?? 'incidents'}
                      value={draft.filter ?? ''}
                      onChange={(filter) => setDraft((old) => ({ ...old, filter }))}
                      label="The filter of the dashboard"
                      placeholder="No filter"
                    />
                  </div>
                  <Select
                    label="Opens on"
                    value={draft.timeRange}
                    onChange={(timeRange) => setDraft((old) => ({ ...old, timeRange }))}
                    options={RANGES.map((item) => ({ value: item.id, label: item.label }))}
                    className="self-end"
                  />
                  <Select
                    label="Refresh"
                    value={String(draft.refreshSeconds ?? 0)}
                    onChange={(value) => setDraft((old) => ({ ...old, refreshSeconds: Number(value) }))}
                    options={REFRESH.map((item) => ({ value: String(item.id), label: item.label }))}
                    className="self-end"
                  />
                  <label className="@3xl:col-span-3">
                    <span className="mb-1 block text-xs font-medium text-fg-muted">Description</span>
                    <input
                      type="text"
                      maxLength={1000}
                      value={draft.description ?? ''}
                      onChange={(event) => setDraft((old) => ({ ...old, description: event.target.value }))}
                      className={`${FIELD} w-full`}
                    />
                  </label>
                </div>
              )}

              <div className="p-6">
                {shown.widgets.length === 0 ? (
                  <EmptyState
                    title="No widget yet"
                    message={
                      editing
                        ? 'Add a widget: a number, a trend, bars, a table…'
                        : shown.canEdit
                          ? 'Edit the dashboard to add its first widget.'
                          : 'This dashboard is empty.'
                    }
                  />
                ) : (
                  <Grid
                    widgets={shown.widgets}
                    editing={editing}
                    onChange={setWidgets}
                    onEdit={setEditingWidget}
                    onMenu={(event, widget) =>
                      menu(event, {
                        title: widget.title || 'A widget',
                        actions: editing
                          ? [{ label: 'Edit…', icon: Pencil, onSelect: () => setEditingWidget(widget) }]
                          : [],
                        copy: [{ label: 'Copy the query', text: widget.entity ? widgetQuery(widget, shown) : '' }],
                        record: widget,
                        danger: editing
                          ? [
                              {
                                label: 'Remove',
                                icon: Trash2,
                                onSelect: () =>
                                  setWidgets(compactGrid(draft.widgets.filter((item) => item.id !== widget.id))),
                              },
                            ]
                          : [],
                      })
                    }
                    onDuplicate={(widget) =>
                      setWidgets(
                        compactGrid([...draft.widgets, { ...widget, id: generateId(), y: widget.y + widget.h }]),
                      )
                    }
                    onRemove={(widget) =>
                      setWidgets(compactGrid(draft.widgets.filter((item) => item.id !== widget.id)))
                    }
                    render={(widget, { asTable }) => (
                      <Widget
                        widget={widget}
                        board={shown}
                        range={editing ? draft.timeRange : range}
                        tick={tick}
                        asTable={asTable}
                        onDrill={editing ? null : setDrill}
                        onOpenIncident={editing ? null : onOpenIncident}
                      />
                    )}
                  />
                )}
              </div>
            </>
          )}
        </div>
      </div>

      {adding && (
        <Modal open onClose={() => setAdding(false)} title="Add a widget" maxWidth="max-w-2xl">
          <ul className="grid gap-2 sm:grid-cols-2">
            {TYPES.map((type) => (
              <li key={type.id}>
                <button
                  type="button"
                  onClick={() => addWidget(type.id)}
                  className="w-full border border-line p-3 text-left hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  <span className="block text-sm font-semibold text-fg">{type.label}</span>
                  <span className="block text-xs text-fg-muted">{type.hint}</span>
                </button>
              </li>
            ))}
          </ul>
        </Modal>
      )}
      {editingWidget && draft && (
        <WidgetEditor
          widget={draft.widgets.find((item) => item.id === editingWidget.id) ?? editingWidget}
          board={draft}
          range={draft.timeRange}
          onClose={() => setEditingWidget(null)}
          onSave={(widget) => {
            setWidgets(
              arrange(draft.widgets, widget.id, widget).map((item) =>
                item.id === widget.id ? { ...widget, x: item.x, y: item.y, w: item.w, h: item.h } : item,
              ),
            )
            setEditingWidget(null)
          }}
        />
      )}
      {drill && (
        <DrillDialog
          what={drill}
          onClose={() => setDrill(null)}
          onOpenIncident={(id) => {
            setDrill(null)
            onOpenIncident(id)
          }}
        />
      )}
      {sharing && board && (
        <ShareDialog
          board={board}
          onClose={() => setSharing(false)}
          onSaved={(saved) => {
            setBoard(saved)
            setSharing(false)
            reload()
          }}
        />
      )}
      {removing && board && (
        <Modal
          open
          onClose={() => setRemoving(false)}
          title={`Delete "${board.name}"?`}
          footer={
            <>
              <Button variant="secondary" onClick={() => setRemoving(false)}>
                Cancel
              </Button>
              <Button variant="danger" onClick={remove}>
                Delete
              </Button>
            </>
          }
        >
          <p className="text-sm text-fg-muted">
            {board.shared ? 'It is shared: whoever sees it loses it too. ' : ''}Nothing it shows is deleted: a dashboard
            only asks.
          </p>
        </Modal>
      )}
    </section>
  )
}
