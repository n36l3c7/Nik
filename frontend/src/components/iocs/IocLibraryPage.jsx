import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  BellRing,
  Download,
  Eye,
  Link2,
  ListPlus,
  Pencil,
  Plus,
  Rss,
  ShieldQuestion,
  Square,
  Trash2,
} from 'lucide-react'
import { api } from '../../services/api.js'
import { copyText } from '../../lib/download.js'
import { formatRelative } from '../../lib/time.js'
import { useIocLibrary } from '../../context/IocLibraryContext.jsx'
import { IocValue } from '../../context/IocLookupContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { useAuth } from '../../context/AuthContext.jsx'
import { verdictMeta } from '../../domain/enrichment.js'
import { IOC_TYPES } from '../../domain/iocs.js'
import {
  EMPTY_FILTERS,
  ORIGIN_LABELS,
  QUICK_FILTERS,
  libraryPath,
  libraryQuery,
  scopeFilters,
  verdictRowClass,
} from '../../domain/iocLibrary.js'
import SortHeader from '../tabs/network/SortHeader.jsx'
import { Badge, Button, EmptyState, MicroSkull, Modal, Select, StatCard } from '../ui/index.js'
import EditIocDialog from './EditIocDialog.jsx'

/*
 * The IoC library in the main area: every indicator Nik knows (or one list),
 * filtered, sorted and paged by the server. Rows are tinted by verdict only.
 * A selection, a list or the whole filter can be checked, exported, put in a
 * list or removed.
 */

const PAGE = 100
const INPUT =
  'h-8 border border-line bg-canvas px-2.5 font-mono text-xs text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const key = (row) => `${row.type}\n${row.value}`
const pair = (row) => ({ type: row.type, value: row.value })

const COLUMNS = [
  { key: 'type', label: 'Type' },
  { key: 'value', label: 'Value' },
  { key: 'verdict', label: 'Verdict' },
  { key: 'score', label: 'Score' },
  { key: null, label: 'Lists' },
  { key: 'incidents', label: 'Incidents' },
  { key: 'origin', label: 'Origin' },
  { key: 'checked', label: 'Checked' },
]

function CheckBanner({ check, onStop }) {
  const share = check.total ? Math.round((check.done / check.total) * 100) : 0
  const flagged = (check.verdicts.malicious ?? 0) + (check.verdicts.suspicious ?? 0)
  const waiting = check.status === 'waiting'
  return (
    <section
      role="status"
      aria-label="Bulk check"
      className={`border px-3.5 py-2.5 ${waiting ? 'border-med-line bg-med-soft/50' : 'border-info-line bg-info-soft/30'}`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
        <span>
          <b>{waiting ? 'Check waiting' : 'Checking'}</b> · {check.label} ·{' '}
          <span className="font-mono tabular-nums">
            {check.done} of {check.total}
          </span>
          {flagged > 0 && <span className="text-fg-muted"> · {flagged} flagged so far</span>}
        </span>
        <Button size="xs" variant="secondary" icon={Square} onClick={onStop}>
          Stop
        </Button>
      </div>
      <div className="mt-2 flex h-1.5 bg-line-soft" aria-hidden="true">
        <i className={`block h-full ${waiting ? 'bg-med-line' : 'bg-accent'}`} style={{ width: `${share}%` }} />
      </div>
      {check.message && <p className="mt-1.5 text-xs text-fg">{check.message}</p>}
    </section>
  )
}

function Alerts({ onOpenIncident }) {
  const { openView, markAlertsSeen, alerts: unseen } = useIocLibrary()
  const [alerts, setAlerts] = useState(null)
  useEffect(() => {
    api
      .get('/iocs/alerts')
      .then((res) => setAlerts(res.alerts))
      .catch(() => setAlerts([]))
  }, [unseen])
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-bold">Alerts</h2>
          <p className="text-sm text-fg-muted">An incident came to hold an indicator of a watched list.</p>
        </div>
        {unseen > 0 && (
          <Button variant="secondary" onClick={markAlertsSeen}>
            Mark {unseen} as seen
          </Button>
        )}
      </div>
      {alerts === null ? (
        <MicroSkull className="text-lg text-fg-muted" />
      ) : alerts.length === 0 ? (
        <EmptyState
          icon={BellRing}
          title="No alerts"
          message='Turn on "Watch this list" on a list: Nik tells you here when an incident holds one of its indicators.'
        />
      ) : (
        <ul className="border border-line">
          {alerts.map((alert) => (
            <li
              key={alert.id}
              className={`flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-line-soft px-3 py-2 text-sm last:border-b-0 ${alert.seen ? '' : 'bg-high-soft/40'}`}
            >
              {!alert.seen && <Badge color="red">new</Badge>}
              <span className="font-mono text-xs text-fg-muted">{alert.type}</span>
              <IocValue type={alert.type} value={alert.value} className="break-all font-mono text-xs" />
              <span className="text-fg-muted">of</span>
              <button
                type="button"
                className="text-link hover:underline"
                onClick={() => openView({ kind: 'list', id: alert.list.id })}
              >
                {alert.list.name}
              </button>
              <span className="text-fg-muted">is in</span>
              <button
                type="button"
                className="text-link hover:underline"
                onClick={() => onOpenIncident(alert.incident.id)}
              >
                {alert.incident.name}
              </button>
              <span className="ml-auto font-mono text-[11px] text-fg-subtle">{formatRelative(alert.at)}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

/** @param {{ onOpenIncident: (id: string) => void }} props */
export default function IocLibraryPage({ onOpenIncident }) {
  const library = useIocLibrary()
  const { view, quick, version, refresh, lists, checks, openView, openAdd, openExport, openCheck, openListForm } =
    library
  const { showToast } = useToast()
  const { currentUser } = useAuth()
  const listId = view?.kind === 'list' ? view.id : null
  const list = listId ? (lists.find((entry) => entry.id === listId) ?? null) : null

  const [filters, setFilters] = useState(EMPTY_FILTERS)
  const [sort, setSort] = useState(null)
  const [offset, setOffset] = useState(0)
  const [data, setData] = useState(null) // { iocs, total }
  const [detail, setDetail] = useState(null) // the list's counts
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(() => new Map())
  const [wholeFilter, setWholeFilter] = useState(false)
  const [editing, setEditing] = useState(null)
  const [confirm, setConfirm] = useState(null) // { title, message, action, run }
  const [listMenu, setListMenu] = useState(false)
  const requestRef = useRef(0)

  // The quick filter of the panel sets the filters of the "all" view.
  const quickFilters = useMemo(
    () => (listId ? {} : (QUICK_FILTERS.find((f) => f.id === quick)?.filters ?? {})),
    [listId, quick],
  )
  const effective = useMemo(() => ({ ...filters, ...quickFilters }), [filters, quickFilters])

  // A different view starts from its first page with nothing selected.
  useEffect(() => {
    setOffset(0)
    setSelected(new Map())
    setWholeFilter(false)
  }, [listId, quick, filters, sort])
  useEffect(() => setFilters(EMPTY_FILTERS), [listId])

  useEffect(() => {
    if (!view || view.kind === 'alerts') return undefined
    const id = ++requestRef.current
    const timer = setTimeout(
      () => {
        api
          .get(`/iocs?${libraryQuery({ filters: effective, list: listId, sort, offset, limit: PAGE })}`)
          .then((res) => id === requestRef.current && (setData(res), setError(null)))
          .catch((err) => id === requestRef.current && setError(err.message))
      },
      filters.q ? 250 : 0,
    )
    return () => clearTimeout(timer)
  }, [view, effective, listId, sort, offset, version, filters.q])

  useEffect(() => {
    if (!listId) {
      setDetail(null)
      return
    }
    api
      .get(`/iocs/lists/${listId}`)
      .then(setDetail)
      .catch((err) => setError(err.message))
  }, [listId, version])

  const rows = useMemo(() => data?.iocs ?? [], [data])
  const total = data?.total ?? 0
  const allOnPage = rows.length > 0 && rows.every((row) => selected.has(key(row)))
  const count = wholeFilter ? total : selected.size
  const scope = useCallback(
    () =>
      wholeFilter || selected.size === 0
        ? listId && !Object.keys(scopeFilters(effective)).length
          ? { list: listId }
          : { filters: scopeFilters(effective, listId) }
        : { items: [...selected.values()].map(pair) },
    [wholeFilter, selected, listId, effective],
  )
  const title = list?.name ?? (QUICK_FILTERS.find((f) => f.id === quick)?.label || 'All indicators')
  const scopeLabel = count && !wholeFilter ? `${count} selected` : title

  const toggle = (row) =>
    setSelected((current) => {
      const next = new Map(current)
      if (next.has(key(row))) next.delete(key(row))
      else next.set(key(row), row)
      return next
    })
  const togglePage = () => {
    setWholeFilter(false)
    setSelected((current) => {
      const next = new Map(current)
      for (const row of rows) allOnPage ? next.delete(key(row)) : next.set(key(row), row)
      return next
    })
  }
  const clear = () => {
    setSelected(new Map())
    setWholeFilter(false)
  }
  const act = async (run, done) => {
    try {
      const result = await run()
      showToast({ message: done(result) })
      clear()
      refresh()
    } catch (err) {
      showToast({ message: err.message })
    }
  }
  const addToList = (target) =>
    act(
      () => api.post(`/iocs/lists/${target.id}/items`, scope()),
      (res) => `${res.added} added to "${target.name}".`,
    )
  const removeFromList = () =>
    act(
      () => api.post(`/iocs/lists/${listId}/items/remove`, { items: [...selected.values()].map(pair) }),
      (res) => `${res.removed} taken out of the list. They stay in the library.`,
    )
  const remove = () =>
    act(
      () => api.post('/iocs/remove', scope()),
      (res) => `${res.removed} removed.${res.kept ? ` ${res.kept} stay: an incident holds them.` : ''}`,
    )
  const stop = (check) => api.post(`/iocs/checks/${check.id}/stop`, {}).then(refresh)
  const feedUrl = list ? `${window.location.origin}/api/iocs/lists/${list.id}/feed` : ''
  const canDelete = list && (currentUser?.role === 'admin' || list.createdBy === currentUser?.username)

  if (!view) return null
  if (view.kind === 'alerts') return <Alerts onOpenIncident={onOpenIncident} />
  if (listId && lists.length > 0 && !list)
    return <EmptyState icon={ShieldQuestion} title="List not found" message="It may have been removed." />

  const running = checks.filter((check) => check.status === 'running' || check.status === 'waiting')
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="flex flex-wrap items-center gap-2 text-lg font-bold">
            {title}
            {list?.watch && (
              <Badge color="cyan" title="An alert when an incident holds one of its indicators">
                <Eye className="h-3 w-3" aria-hidden="true" /> watched
              </Badge>
            )}
            {list && <Badge color={list.tlp === 'red' ? 'red' : 'slate'}>TLP:{list.tlp.toUpperCase()}</Badge>}
          </h2>
          <p className="text-sm text-fg-muted">
            {list
              ? [list.description, `by ${list.createdBy || 'unknown'}`, formatRelative(list.createdAt)]
                  .filter(Boolean)
                  .join(' · ')
              : 'Every indicator Nik knows: seen in an incident, added by hand or imported.'}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => openCheck(listId ? { list: listId } : { filters: scopeFilters(effective) }, title)}>
            Check all {total}
          </Button>
          <Button
            variant="secondary"
            icon={Download}
            onClick={() => openExport(listId ? { list: listId } : { filters: scopeFilters(effective) }, title, total)}
          >
            Export
          </Button>
          <Button variant="secondary" icon={Plus} onClick={() => openAdd(listId ? { list: listId } : {})}>
            Add
          </Button>
          {list && (
            <>
              <Button
                variant="secondary"
                icon={Link2}
                onClick={async () =>
                  showToast({
                    message: (await copyText(`${window.location.origin}${libraryPath(view)}`))
                      ? 'Link copied.'
                      : 'The browser refused to copy.',
                  })
                }
              >
                Copy link
              </Button>
              <Button variant="secondary" icon={Rss} onClick={() => setListMenu(true)}>
                Feed
              </Button>
              <Button
                variant="secondary"
                icon={Pencil}
                aria-label="Edit the list"
                onClick={() => openListForm({ list })}
              />
              {canDelete && (
                <Button
                  variant="secondary"
                  icon={Trash2}
                  aria-label="Remove the list"
                  onClick={() =>
                    setConfirm({
                      title: 'Remove the list?',
                      message: `"${list.name}" is removed. Its ${list.count} indicators stay in the library.`,
                      action: 'Remove the list',
                      run: async () => {
                        await api.del(`/iocs/lists/${list.id}`)
                        showToast({ message: 'List removed.' })
                        refresh()
                        openView({ kind: 'all' })
                      },
                    })
                  }
                />
              )}
            </>
          )}
        </div>
      </div>

      {running.map((check) => (
        <CheckBanner key={check.id} check={check} onStop={() => stop(check)} />
      ))}

      {detail && (
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
          <StatCard label="Indicators" value={detail.counts.all} />
          <StatCard
            label="Malicious"
            value={detail.counts.malicious}
            tone={detail.counts.malicious ? 'danger' : 'default'}
          />
          <StatCard label="Suspicious" value={detail.counts.suspicious} />
          <StatCard label="Harmless" value={detail.counts.harmless} />
          <StatCard label="Not checked" value={detail.counts.unchecked} />
          <StatCard label="In incidents" value={detail.counts.inIncidents} />
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <input
          type="search"
          aria-label="Filter indicators"
          placeholder="filter by value, tag, note, list…"
          value={filters.q}
          onChange={(event) => setFilters({ ...filters, q: event.target.value })}
          className={`${INPUT} min-w-0 flex-1 sm:max-w-xs`}
        />
        <Select
          value={filters.type}
          onChange={(type) => setFilters({ ...filters, type })}
          options={[
            { value: '', label: 'All types' },
            ...Object.entries(IOC_TYPES).map(([value, meta]) => ({ value, label: meta.label })),
          ]}
        />
        {!quickFilters.verdict && (
          <Select
            value={filters.verdict}
            onChange={(verdict) => setFilters({ ...filters, verdict })}
            options={[
              { value: '', label: 'Any verdict' },
              { value: 'flagged', label: 'Malicious or suspicious' },
              { value: 'malicious', label: 'Malicious' },
              { value: 'suspicious', label: 'Suspicious' },
              { value: 'harmless', label: 'Harmless' },
              { value: 'none', label: 'Never checked' },
            ]}
          />
        )}
        {!quickFilters.origin && (
          <Select
            value={filters.origin}
            onChange={(origin) => setFilters({ ...filters, origin })}
            options={[
              { value: '', label: 'Any origin' },
              { value: 'incident', label: 'From an incident' },
              { value: 'manual', label: 'Added by hand' },
              { value: 'import', label: 'Imported' },
            ]}
          />
        )}
        <span className="ml-auto font-mono text-xs text-fg-muted">
          {total === 0 ? '0' : `${offset + 1}–${Math.min(offset + PAGE, total)}`} of {total}
        </span>
      </div>

      {count > 0 && (
        <section
          aria-label="Selection"
          className="flex flex-wrap items-center justify-between gap-2 border border-accent bg-accent-soft px-3 py-2 text-sm"
        >
          <span>
            <b>{count}</b> selected
            {!wholeFilter && allOnPage && total > rows.length && (
              <>
                {' · '}
                <button type="button" className="text-link hover:underline" onClick={() => setWholeFilter(true)}>
                  select all {total}
                </button>
              </>
            )}
            {' · '}
            <button type="button" className="text-link hover:underline" onClick={clear}>
              clear
            </button>
          </span>
          <span className="flex flex-wrap gap-2">
            <Button size="sm" onClick={() => openCheck(scope(), scopeLabel)}>
              Check {count}
            </Button>
            <Select
              value=""
              onChange={(target) => {
                if (target === 'new') openListForm({ scope: scope(), count })
                else if (target) addToList(lists.find((entry) => entry.id === target))
              }}
              options={[
                { value: '', label: 'Add to a list…' },
                { value: 'new', label: '+ New list' },
                ...lists
                  .filter((entry) => entry.id !== listId)
                  .map((entry) => ({ value: entry.id, label: entry.name })),
              ]}
            />
            <Button
              size="sm"
              variant="secondary"
              icon={Download}
              onClick={() => openExport(scope(), scopeLabel, count)}
            >
              Export
            </Button>
            {listId && !wholeFilter && (
              <Button size="sm" variant="secondary" onClick={removeFromList}>
                Take out of the list
              </Button>
            )}
            <Button
              size="sm"
              variant="secondary"
              icon={Trash2}
              onClick={() =>
                setConfirm({
                  title: `Remove ${count} indicator${count === 1 ? '' : 's'}?`,
                  message:
                    'They leave the library and every list. An indicator an incident still holds stays, as part of that incident.',
                  action: 'Remove',
                  run: remove,
                })
              }
            >
              Remove
            </Button>
          </span>
        </section>
      )}

      {error ? (
        <p role="alert" className="font-mono text-sm text-high">
          {error}
        </p>
      ) : data === null ? (
        <MicroSkull className="text-lg text-fg-muted" />
      ) : rows.length === 0 ? (
        <EmptyState
          icon={ListPlus}
          title={total === 0 && !filters.q ? 'No indicators here' : 'Nothing matches'}
          message="Add one or many: type, paste, or drop a file of indicators anywhere."
          action={
            <Button icon={Plus} onClick={() => openAdd(listId ? { list: listId } : {})}>
              Add indicators
            </Button>
          }
        />
      ) : (
        <div className="overflow-x-auto border border-line">
          <table aria-label="Indicators" className="w-full min-w-[56rem] border-collapse font-mono text-xs">
            <thead className="bg-panel text-left text-fg-muted">
              <tr>
                <th className="w-8 px-2 py-1.5">
                  <input type="checkbox" aria-label="Select the page" checked={allOnPage} onChange={togglePage} />
                </th>
                {COLUMNS.map((column) =>
                  column.key ? (
                    <SortHeader
                      key={column.label}
                      label={column.label}
                      sort={sort}
                      sortKey={column.key}
                      onSort={setSort}
                    />
                  ) : (
                    <th key={column.label} className="px-2 py-1.5 font-normal">
                      {column.label}
                    </th>
                  ),
                )}
                <th className="w-8" />
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const meta = row.verdict ? verdictMeta(row.verdict) : null
                const picked = wholeFilter || selected.has(key(row))
                return (
                  <tr
                    key={key(row)}
                    className={`border-t border-line-soft ${verdictRowClass(row.verdict)} ${picked ? 'outline outline-1 -outline-offset-1 outline-accent/60' : ''}`}
                  >
                    <td className="px-2 py-1.5">
                      <input
                        type="checkbox"
                        aria-label={`Select ${row.value}`}
                        checked={picked}
                        disabled={wholeFilter}
                        onChange={() => toggle(row)}
                      />
                    </td>
                    <td className="px-2 py-1.5 text-fg-muted">{row.type}</td>
                    <td className="max-w-[22rem] px-2 py-1.5">
                      <IocValue type={row.type} value={row.value} className="break-all" />
                      {(row.tags.length > 0 || row.note || row.expired) && (
                        <span className="mt-0.5 block text-[11px] text-fg-subtle">
                          {row.expired && <span className="text-med">expired {row.expires} · </span>}
                          {row.tags.map((tag) => `#${tag}`).join(' ')}
                          {row.tags.length > 0 && row.note ? ' · ' : ''}
                          <span className="font-sans">{row.note}</span>
                        </span>
                      )}
                    </td>
                    <td className="px-2 py-1.5">
                      {meta ? (
                        <Badge color={meta.color}>{meta.label}</Badge>
                      ) : row.neverSent ? (
                        <Badge title={row.neverSent}>never sent out</Badge>
                      ) : (
                        <Badge>not checked</Badge>
                      )}
                    </td>
                    <td className="px-2 py-1.5 tabular-nums">
                      {row.score ?? <span className="text-fg-subtle">—</span>}
                    </td>
                    <td className="px-2 py-1.5">
                      <span className="flex flex-wrap gap-1">
                        {row.lists.length === 0 && <span className="text-fg-subtle">—</span>}
                        {row.lists.map((entry) => (
                          <button
                            key={entry.id}
                            type="button"
                            onClick={() => openView({ kind: 'list', id: entry.id })}
                            className="max-w-[11rem] truncate border border-line px-1.5 text-[11px] text-fg-muted hover:border-accent hover:text-fg"
                          >
                            {entry.name}
                          </button>
                        ))}
                      </span>
                    </td>
                    <td className="px-2 py-1.5 tabular-nums">{row.incidents}</td>
                    <td className="px-2 py-1.5 text-fg-muted">{ORIGIN_LABELS[row.origin] ?? row.origin}</td>
                    <td className="whitespace-nowrap px-2 py-1.5 text-fg-muted">
                      {row.checkedAt ? formatRelative(row.checkedAt) : <span className="text-fg-subtle">never</span>}
                    </td>
                    <td className="px-1 py-1.5">
                      <button
                        type="button"
                        aria-label={`Edit ${row.value}`}
                        onClick={() => setEditing(row)}
                        className="p-1 text-fg-subtle hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                      >
                        <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {total > PAGE && (
        <div className="flex items-center justify-end gap-2">
          <Button
            size="sm"
            variant="secondary"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE))}
          >
            Previous
          </Button>
          <Button
            size="sm"
            variant="secondary"
            disabled={offset + PAGE >= total}
            onClick={() => setOffset(offset + PAGE)}
          >
            Next
          </Button>
        </div>
      )}

      <EditIocDialog
        row={editing}
        onClose={() => setEditing(null)}
        onSaved={() => {
          setEditing(null)
          refresh()
        }}
      />
      <Modal
        open={Boolean(confirm)}
        onClose={() => setConfirm(null)}
        title={confirm?.title ?? ''}
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirm(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={async () => {
                const run = confirm.run
                setConfirm(null)
                await run()
              }}
            >
              {confirm?.action}
            </Button>
          </>
        }
      >
        <p>{confirm?.message}</p>
      </Modal>
      <Modal open={listMenu && Boolean(list)} onClose={() => setListMenu(false)} title="Feed of the list">
        <div className="space-y-3">
          <p>
            The list as it is now, for a firewall, a SIEM or a SOAR to poll. Allowlisted and expired indicators are left
            out.
          </p>
          <pre className="overflow-x-auto border border-line bg-canvas p-2.5 font-mono text-[11px]">{feedUrl}</pre>
          <ul className="list-disc space-y-1 pl-5 text-sm text-fg-muted">
            <li>
              Sign the request with an API key (Settings → API keys, read scope): the{' '}
              <span className="font-mono">X-API-Key</span> header, or HTTP Basic with the key as the password.
            </li>
            <li>
              <span className="font-mono">?format=txt</span> (default), <span className="font-mono">csv</span>,{' '}
              <span className="font-mono">json</span>, <span className="font-mono">stix</span>,{' '}
              <span className="font-mono">misp</span>; <span className="font-mono">&amp;types=ip,domain</span>;{' '}
              <span className="font-mono">&amp;flagged=true</span> for malicious and suspicious only.
            </li>
            <li>A TLP:RED list has no feed.</li>
          </ul>
          <Button
            variant="secondary"
            icon={Link2}
            onClick={async () =>
              showToast({ message: (await copyText(feedUrl)) ? 'Address copied.' : 'The browser refused to copy.' })
            }
          >
            Copy the address
          </Button>
        </div>
      </Modal>
    </div>
  )
}
