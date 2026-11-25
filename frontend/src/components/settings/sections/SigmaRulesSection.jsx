import { Suspense, lazy, useCallback, useEffect, useMemo, useState } from 'react'
import { AlertCircle, Plus, RefreshCw, ShieldAlert } from 'lucide-react'
import { useAuth } from '../../../context/AuthContext.jsx'
import { useToast } from '../../../context/ToastContext.jsx'
import { LEVEL_FILTER_OPTIONS } from '../../../domain/detections.js'
import {
  ENABLED_OPTIONS,
  KIND_OPTIONS,
  STATUS_OPTIONS,
  SUPPORTED_OPTIONS,
  bulkBody,
  bulkText,
  listParams,
  logSourceText,
  packLabel,
  packOptions,
  pageOf,
  productOptions,
  summaryLine,
} from '../../../domain/sigma.js'
import { withFilter } from '../../../domain/serverTable.js'
import { formatRelative } from '../../../lib/time.js'
import { sigmaRules } from '../../../services/api.js'
import LevelBadge from '../../evidence/LevelBadge.jsx'
import { Badge, Button, Select, ServerTable, Wait } from '../../ui/index.js'
import Switch from './Switch.jsx'

/*
 * Sigma rules (Settings → Rule sets). The rules the worker runs over host evidence as it is read: the
 * ones of the Nik pack, those of packs installed from the catalogue and those written here. Anyone who may
 * read sees the list; `rules.manage` switches, writes, deletes and checks again (the server holds the same
 * line). The editor is its own module, loaded when a rule is opened, so the editor of YAML is not part of
 * the settings page.
 */

const SigmaRuleEditor = lazy(() => import('./SigmaRuleEditor.jsx'))

const FILTER_NAMES = ['pack', 'level', 'status', 'enabled', 'supported', 'product', 'category', 'service', 'kind']
const INPUT =
  'w-32 border border-line bg-canvas px-2 py-1.5 font-mono text-[13px] text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/** A text filter, applied on Enter or when it is left. */
function TextFilter({ label, value, onCommit }) {
  const [text, setText] = useState(value)
  useEffect(() => setText(value), [value])
  const commit = () => text.trim() !== value && onCommit(text.trim())
  return (
    <label className="inline-flex items-center gap-2">
      <span className="whitespace-nowrap font-mono text-xs text-fg-muted">{label}</span>
      <input
        value={text}
        onChange={(event) => setText(event.target.value)}
        onBlur={commit}
        onKeyDown={(event) => event.key === 'Enter' && commit()}
        className={INPUT}
      />
    </label>
  )
}

export default function SigmaRulesSection() {
  const { can } = useAuth()
  const { showToast } = useToast()
  const canManage = can('rules.manage')
  const [editing, setEditing] = useState(null) // null: the list; { id }: a rule; { id: null }: a new one
  const [filters, setFilters] = useState({})
  const [summary, setSummary] = useState(null)
  const [summaryError, setSummaryError] = useState('')
  const [version, setVersion] = useState(0)
  const [switched, setSwitched] = useState({}) // id -> enabled, what was switched here since the list was read
  const [busy, setBusy] = useState(false)

  // The line over the list, read again when something changed.
  useEffect(() => {
    const controller = new AbortController()
    sigmaRules
      .summary({ signal: controller.signal })
      .then((answer) => {
        setSummary(answer)
        setSummaryError('')
      })
      .catch((failure) => {
        if (failure?.name !== 'AbortError') setSummaryError(failure.message || 'The rules could not be counted.')
      })
    return () => controller.abort()
  }, [version])

  const refresh = useCallback(() => {
    setSwitched({})
    setVersion((n) => n + 1)
  }, [])

  const load = useCallback(
    async ({ cursor, limit, order, filters: asked, signal }) =>
      pageOf(await sigmaRules.list(listParams({ filters: asked, order, cursor, limit }), { signal })),
    [],
  )

  const toggle = useCallback(
    async (rule, enabled) => {
      try {
        await sigmaRules.setEnabled(rule.id, enabled)
        setSwitched((before) => ({ ...before, [rule.id]: enabled }))
        setVersion((n) => n + 1)
      } catch (failure) {
        showToast({ message: failure.message || 'The rule could not be switched.' })
      }
    },
    [showToast],
  )

  const bulk = useCallback(
    async (enabled, scope) => {
      try {
        const result = await sigmaRules.bulk(bulkBody(enabled, scope))
        showToast({ message: bulkText(enabled, result) })
        refresh()
      } catch (failure) {
        showToast({ message: failure.message || 'The rules could not be switched.' })
      }
    },
    [showToast, refresh],
  )

  const recheck = async () => {
    setBusy(true)
    try {
      await sigmaRules.recheck()
      showToast({ message: 'The worker reads the rules again in the background. The counts update when it is done.' })
      setTimeout(refresh, 4000)
    } catch (failure) {
      showToast({
        message:
          failure.status === 503
            ? 'The forensics worker is not configured: the rules cannot be checked.'
            : failure.message || 'The rules could not be checked again.',
      })
    } finally {
      setBusy(false)
    }
  }

  const columns = useMemo(
    () => [
      {
        key: 'enabled',
        label: 'On',
        className: 'w-px',
        render: (row) => (
          <span onClick={(event) => event.stopPropagation()} onKeyDown={(event) => event.stopPropagation()}>
            <Switch
              checked={switched[row.id] ?? row.enabled}
              label={`${row.title}: ${(switched[row.id] ?? row.enabled) ? 'on' : 'off'}`}
              disabled={!canManage || (!row.supported && !(switched[row.id] ?? row.enabled))}
              onChange={(value) => toggle(row, value)}
            />
          </span>
        ),
      },
      {
        key: 'title',
        label: 'Rule',
        order: 'title',
        reverse: false,
        render: (row) => (
          <div className="min-w-0 max-w-xl">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium text-fg">{row.title}</span>
              {row.edited && (
                <Badge color="violet" title="A person changed this rule of the pack">
                  edited
                </Badge>
              )}
              {row.kind === 'correlation' && <Badge color="cyan">correlation</Badge>}
            </div>
            {!row.supported && (
              <p className="mt-0.5 text-xs text-med-fg">Nik cannot run it: {row.reason || 'reason not given'}</p>
            )}
            {row.author && <p className="mt-0.5 text-xs text-fg-muted">by {row.author}</p>}
          </div>
        ),
      },
      { key: 'level', label: 'Level', order: '-level', render: (row) => <LevelBadge level={row.level} empty="—" /> },
      {
        key: 'pack',
        label: 'Pack',
        hideable: true,
        render: (row) => <span className="text-xs">{packLabel(row, summary)}</span>,
      },
      {
        key: 'status',
        label: 'Status',
        hideable: true,
        render: (row) => <span className="font-mono text-xs text-fg-muted">{row.status || '—'}</span>,
      },
      {
        key: 'logsource',
        label: 'Log source',
        hideable: true,
        render: (row) => <span className="font-mono text-xs text-fg-muted">{logSourceText(row)}</span>,
      },
      {
        key: 'updatedAt',
        label: 'Changed',
        order: '-updated',
        reverse: false,
        hideable: true,
        render: (row) => (
          <span className="whitespace-nowrap text-xs text-fg-muted">
            {row.updatedAt ? formatRelative(row.updatedAt) : '—'}
          </span>
        ),
      },
    ],
    [summary, switched, canManage, toggle],
  )

  if (editing) {
    return (
      <Suspense
        fallback={
          <div className="p-2">
            <Wait>Opening the editor…</Wait>
          </div>
        }
      >
        <SigmaRuleEditor
          key={editing.id ?? 'new'}
          ruleId={editing.id}
          canManage={canManage}
          onClose={(changed) => {
            setEditing(null)
            if (changed) refresh()
          }}
        />
      </Suspense>
    )
  }

  const setFilter = (name, value) => setFilters((before) => withFilter(before, name, value))
  const toolbar = (
    <div className="flex flex-wrap items-center gap-2">
      <Select
        value={filters.pack ?? ''}
        onChange={(v) => setFilter('pack', v)}
        options={packOptions(summary)}
        label="Pack"
      />
      <Select
        value={filters.level ?? ''}
        onChange={(v) => setFilter('level', v)}
        options={LEVEL_FILTER_OPTIONS}
        label="Level"
      />
      <Select
        value={filters.status ?? ''}
        onChange={(v) => setFilter('status', v)}
        options={STATUS_OPTIONS}
        label="Status"
      />
      <Select
        value={filters.enabled ?? ''}
        onChange={(v) => setFilter('enabled', v)}
        options={ENABLED_OPTIONS}
        label="Switch"
      />
      <Select
        value={filters.supported ?? ''}
        onChange={(v) => setFilter('supported', v)}
        options={SUPPORTED_OPTIONS}
        label="Support"
      />
      <Select
        value={filters.product ?? ''}
        onChange={(v) => setFilter('product', v)}
        options={productOptions(summary, filters.product)}
        label="Product"
      />
      <TextFilter label="Category" value={filters.category ?? ''} onCommit={(v) => setFilter('category', v)} />
      <TextFilter label="Service" value={filters.service ?? ''} onCommit={(v) => setFilter('service', v)} />
      <Select value={filters.kind ?? ''} onChange={(v) => setFilter('kind', v)} options={KIND_OPTIONS} label="Kind" />
    </div>
  )

  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h2 className="flex items-center gap-2 text-base font-semibold text-fg">
            <ShieldAlert className="h-4 w-4 text-accent" aria-hidden="true" />
            Sigma rules
          </h2>
          <p className="mt-1 text-sm text-fg-muted">
            The rules the worker runs over event logs, command history, endpoint artifacts and browser history as each
            file is read. A match is a detection on the record, with the level of the rule.
          </p>
        </div>
        {canManage && (
          <div className="flex gap-2">
            <Button
              variant="secondary"
              icon={RefreshCw}
              waiting={busy}
              disabled={busy}
              title="Have the worker read every rule again with its present version"
              onClick={recheck}
            >
              Check again
            </Button>
            <Button icon={Plus} onClick={() => setEditing({ id: null })}>
              New rule
            </Button>
          </div>
        )}
      </div>

      {summaryError && (
        <p
          role="alert"
          className="flex items-center gap-2 border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg"
        >
          <AlertCircle className="h-4 w-4 shrink-0" aria-hidden="true" />
          {summaryError}
        </p>
      )}
      {summary && (
        <p role="status" className="font-mono text-xs text-fg-muted">
          {summaryLine(summary)}
        </p>
      )}
      {summary && !summary.workerConfigured && (
        <p role="status" className="border border-med-line bg-med-soft px-3 py-2 text-sm text-med-fg">
          The forensics worker is not configured. Rules cannot be read or checked, so none runs on a file until it is.
        </p>
      )}
      {!canManage && (
        <p className="text-xs text-fg-muted">
          You can read the rules. Changing them needs the permission to manage rules.
        </p>
      )}

      <ServerTable
        tableKey="sigma-rules"
        load={load}
        columns={columns}
        filters={filters}
        onFiltersChange={setFilters}
        toolbar={toolbar}
        hideChips={FILTER_NAMES}
        refreshKey={version}
        defaultOrder="title"
        searchPlaceholder="Search title, id, name or author…"
        emptyMessage="No rule matches the current filters"
        rowKey={(row) => row.id}
        rowClassName={(row) => `cursor-pointer ${row.supported ? '' : 'opacity-60'}`}
        onRowClick={(row) => setEditing({ id: row.id })}
        selectable={
          canManage
            ? {
                id: (row) => row.id,
                label: (row) => row.title,
                noun: 'rules',
                actions: (rows, picked, scope) => [
                  { id: 'on', label: 'Switch on', onSelect: () => bulk(true, scope) },
                  { id: 'off', label: 'Switch off', onSelect: () => bulk(false, scope) },
                ],
              }
            : null
        }
      />
    </section>
  )
}
