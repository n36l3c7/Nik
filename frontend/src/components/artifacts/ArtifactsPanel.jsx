import { useEffect, useMemo, useState } from 'react'
import {
  Boxes,
  Bug,
  Download,
  FolderOpen,
  Inbox,
  Link2,
  Mail,
  Network,
  Plus,
  FileSearch,
  Tag,
  Upload,
} from 'lucide-react'
import { useArtifacts } from '../../context/ArtifactContext.jsx'
import {
  ARTIFACT_KINDS,
  analyseAsActions,
  artifactMeta,
  artifactPath,
  verdictBadge,
} from '../../domain/artifactRegistry.js'
import { useToast } from '../../context/ToastContext.jsx'
import { formatRelative } from '../../lib/time.js'
import { AsciiSkull, Badge, BulkBar, Button, SelectBox, Wait, useSelection } from '../ui/index.js'
import { useItemMenu } from '../menu/useRowMenu.js'
import { useAuth } from '../../context/AuthContext.jsx'
import { useBulk } from '../../context/BulkContext.jsx'
import { api } from '../../services/api.js'
import QueryInput from '../ui/QueryInput.jsx'
import { useQuerySchema } from '../../services/querySchema.js'
import { writeValue } from '../../domain/query/complete.js'
import { conditionOn, withCondition } from '../../domain/query/builder.js'
import ArtifactTransferDialog from './ArtifactTransferDialog.jsx'
import { exportRequest } from '../../domain/artifactExpiry.js'
import HidePanel from '../layout/HidePanel.jsx'
import { transfer as showTransfer } from '../../lib/transfers.js'

/*
 * The artifacts panel of the sidebar: files, e-mails and captures analysed on
 * their own or in incidents, and scanned addresses, for the whole team, newest first. The filter
 * is a query read by the server ("mine" writes its condition into it); the kind chips count
 * what the query keeps of each kind.
 *
 * The checkbox of an artifact selects it, as in every list (components/ui/useSelection.js); the
 * bar that appears tags, links, analyses again, downloads together or deletes what is selected,
 * or everything the filter keeps.
 */

// How many artifacts one archive holds (the server's limit of an export).
const TOGETHER_MAX = 500

export const KIND_ICONS = { file: Bug, mail: Mail, pcap: Network, url: Link2, mailbox: Inbox }

const CHIP =
  'h-7 px-2.5 border font-mono text-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

function Chip({ active, onClick, children }) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={`${CHIP} ${active ? 'border-accent bg-raised text-fg' : 'border-line text-fg-muted hover:text-fg'}`}
    >
      {children}
    </button>
  )
}

/**
 * @param {{ width: number, onNewAnalysis: () => void, onHide?: () => void }} props
 */
export default function ArtifactsPanel({ width, onNewAnalysis, onHide }) {
  const {
    artifacts,
    counts,
    filters,
    setFilters,
    loading,
    error,
    queryError,
    currentId,
    openArtifact,
    analyseAs,
    refresh,
  } = useArtifacts()
  const { showToast } = useToast()
  const { can, currentUser } = useAuth()
  const schema = useQuerySchema('artifacts')
  // "mine" is a condition of the query: the artifacts this account added.
  const mineCondition = currentUser ? `createdBy:${writeValue(currentUser.username)}` : ''
  const mine = Boolean(mineCondition) && conditionOn(filters.q, 'createdBy', schema) === mineCondition
  const [transfer, setTransfer] = useState(null) // { mode: 'export', ids, label } | { mode: 'import' }
  const { askBulk } = useBulk()
  const canWrite = can('write')
  const total = filters.kind
    ? (counts[filters.kind] ?? 0)
    : ARTIFACT_KINDS.reduce((sum, kind) => sum + (counts[kind.id] ?? 0), 0)
  // What the server is told the filter is, when everything it keeps is selected.
  const query = useMemo(
    () => ({ ...(filters.q.trim() ? { q: filters.q.trim() } : {}), ...(filters.kind ? { kind: filters.kind } : {}) }),
    [filters],
  )
  const pageIds = useMemo(() => artifacts.map((artifact) => artifact.id), [artifacts])
  const picked = useSelection({ filter: JSON.stringify(query), pageIds, total })
  const ask = (action, title, more = {}) =>
    askBulk({
      list: 'artifacts',
      action,
      title,
      selection: picked.body(query),
      onStarted: picked.reset,
      onDone: refresh,
      ...more,
    })
  // One archive made by the server, the files inside an encrypted archive: the export of the artifacts.
  const downloadTogether = async () => {
    try {
      let rows = artifacts.filter((artifact) => picked.has(artifact.id))
      if (picked.all) {
        if (total > TOGETHER_MAX) {
          showToast({ message: `One archive holds ${TOGETHER_MAX} artifacts at most: narrow the filter.` })
          return
        }
        rows = []
        // The whole filter, two hundred at a time (bounded by the limit above).
        for (let from = 0; from < total; from += 200) {
          const params = new URLSearchParams({ ...query, limit: '200', offset: String(from) })
          rows.push(...(await api.get(`/artifacts?${params}`)).artifacts)
        }
      }
      setTransfer(exportRequest(rows))
    } catch (failure) {
      showToast({ message: failure.message })
    }
  }
  const bulkActions = [
    ...(canWrite
      ? [
          {
            id: 'tags',
            label: 'Change the tags…',
            onSelect: () => ask('tags', 'Change the tags', { form: { kind: 'tags' } }),
          },
          { id: 'reanalyse', label: 'Analyse again', onSelect: () => ask('reanalyse', 'Analyse again') },
          {
            id: 'link',
            label: 'Link to an incident…',
            onSelect: () =>
              ask('link', 'Link to an incident', { form: { kind: 'incident', params: (id) => ({ incident: id }) } }),
          },
          {
            id: 'unlink',
            label: 'Take out of an incident…',
            onSelect: () =>
              ask('unlink', 'Take out of an incident', {
                form: { kind: 'incident', params: (id) => ({ incident: id }) },
              }),
          },
          {
            id: 'expiry',
            label: 'Set the expiry…',
            onSelect: () => ask('expiry', 'Set the expiry', { form: { kind: 'date' } }),
          },
        ]
      : []),
    { id: 'download', label: 'Download together…', onSelect: downloadTogether },
    ...(canWrite ? [{ id: 'delete', label: 'Delete…', onSelect: () => ask('delete', 'Delete the artifacts') }] : []),
  ]
  const focusItem = (id) =>
    document.querySelector(`[aria-label="Artifacts"] li[data-row="${CSS.escape(id)}"] button`)?.focus()
  // No incident here: the menu offers what an artifact offers on its own.
  const menu = useItemMenu(null)
  const artifactMenu = (event, artifact) =>
    menu(event, {
      title: artifact.name,
      artifact,
      ...(artifact.kind === 'file' || artifact.kind === 'mail' ? { ioc: { type: 'sha256', value: artifact.ref } } : {}),
      copy: [
        { label: 'name', text: artifact.name },
        { label: 'link', text: `${window.location.origin}${artifactPath(artifact.id)}` },
      ],
      actions: [
        { label: 'Open', icon: FolderOpen, onSelect: () => openArtifact(artifact.id) },
        {
          label: 'Export…',
          icon: Download,
          onSelect: () => setTransfer(exportRequest([artifact])),
        },
        // A file whose name says it is a message or a capture: what it is analysed as opens.
        ...(can('write') ? analyseAsActions(artifact) : []).map((action) => ({
          label: action.label,
          icon: FileSearch,
          onSelect: async () => {
            try {
              const made = await showTransfer(`${action.label}: ${artifact.name}`, () =>
                analyseAs(artifact.id, action.as),
              )
              openArtifact(made.id)
            } catch (error) {
              showToast({ message: `${action.label}: ${error.message}` })
            }
          },
        })),
        ...artifact.tags.slice(0, 5).map((tag) => ({
          label: `Filter by #${tag}`,
          icon: Tag,
          onSelect: () => setFilters({ ...filters, q: tag }),
        })),
      ],
    })
  // Uploads made inside an incident add artifacts too: reload when the panel opens.
  useEffect(() => refresh(), [refresh])
  const every = ARTIFACT_KINDS.reduce((sum, kind) => sum + (counts[kind.id] ?? 0), 0)

  return (
    <aside
      aria-label="Artifacts panel"
      style={{ width }}
      className="flex h-full shrink-0 flex-col border-r border-line bg-sunken"
    >
      {/* Three things share the width of the panel: the title is set tight so its count is not cut. */}
      <div className="flex items-center gap-1.5 border-b border-line px-3 py-3">
        <p className="min-w-0 flex-1 truncate font-mono text-[10px] text-fg-muted">ARTIFACTS · {every}</p>
        {can('write') && (
          <Button size="sm" icon={Plus} onClick={onNewAnalysis}>
            New analysis
          </Button>
        )}
        {onHide && <HidePanel label="Hide the artifacts panel" onClick={onHide} />}
      </div>

      <div className="space-y-2 border-b border-line px-3 py-2.5">
        <QueryInput
          entity="artifacts"
          label="Filter artifacts"
          placeholder="name, hash, tag… or verdict:phishing"
          value={filters.q}
          onChange={(q) => setFilters({ ...filters, q })}
          error={queryError}
        />
        <div className="flex flex-wrap gap-1.5">
          <Chip active={!filters.kind} onClick={() => setFilters({ ...filters, kind: '' })}>
            all
          </Chip>
          {ARTIFACT_KINDS.map((kind) => (
            <Chip
              key={kind.id}
              active={filters.kind === kind.id}
              onClick={() => setFilters({ ...filters, kind: filters.kind === kind.id ? '' : kind.id })}
            >
              {kind.label} {counts[kind.id] ?? 0}
            </Chip>
          ))}
          <Chip
            active={mine}
            onClick={() =>
              setFilters({ ...filters, q: withCondition(filters.q, 'createdBy', mine ? '' : mineCondition, schema) })
            }
          >
            mine
          </Chip>
        </div>
      </div>

      <BulkBar picked={picked} noun="artifacts" actions={bulkActions} className="mx-2 mt-2" />
      {artifacts.length > 0 && (
        <div className="flex items-center gap-1 border-b border-line-soft px-1 font-mono text-[10px] text-fg-muted">
          <SelectBox label="Select the artifacts listed" state={picked.page} onPick={picked.pickPage} />
          <span>{artifacts.length < total ? `the first ${artifacts.length} of ${total}` : `${total} listed`}</span>
        </div>
      )}

      <nav aria-label="Artifacts" className="flex-1 overflow-y-auto">
        {error ? (
          <p role="alert" className="px-3 py-3 font-mono text-xs text-high">
            {error}
          </p>
        ) : artifacts.length === 0 ? (
          <div className="flex flex-col items-center gap-2 px-4 py-8 text-center">
            {loading ? <Wait>Loading the artifacts…</Wait> : <AsciiSkull preset="small" eyes="closed" tone="muted" />}
            <p className="text-sm text-fg-muted">
              {loading
                ? ''
                : filters.q || filters.kind
                  ? 'No artifact matches these filters.'
                  : 'No artifacts yet: start an analysis, or drop a file anywhere.'}
            </p>
          </div>
        ) : (
          <ul>
            {artifacts.map((artifact) => {
              const Icon = KIND_ICONS[artifact.kind] ?? Boxes
              const badge = verdictBadge(artifact)
              const active = artifact.id === currentId
              const ticked = picked.has(artifact.id)
              return (
                <li
                  key={artifact.id}
                  data-row={artifact.id}
                  aria-selected={ticked}
                  className={`flex items-start border-b border-line-soft ${ticked ? 'bg-accent-soft/40' : ''}`}
                  onContextMenu={(event) => artifactMenu(event, artifact)}
                >
                  <SelectBox
                    label={`Select ${artifact.name}`}
                    checked={ticked}
                    onPick={(event) => picked.pick(artifact.id, event)}
                    className="mt-1 shrink-0 pl-1"
                  />
                  <button
                    type="button"
                    onClick={() => openArtifact(artifact.id)}
                    onKeyDown={(event) => {
                      // Space ticks, Shift and an arrow tick the next one too; Enter opens, as it did.
                      const moved = picked.key(event, artifact.id)
                      if (moved) focusItem(moved)
                    }}
                    aria-current={active ? 'true' : undefined}
                    className={[
                      'min-w-0 flex-1 py-2 pl-1 pr-3 text-left transition-colors',
                      'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent',
                      active ? 'bg-panel shadow-[inset_2px_0_0_var(--color-accent)]' : 'hover:bg-panel/60',
                    ].join(' ')}
                  >
                    <span className="flex items-center gap-1.5">
                      <Icon className="h-3.5 w-3.5 shrink-0 text-fg-muted" aria-hidden="true" />
                      <span className="min-w-0 flex-1 truncate font-mono text-[13px] font-semibold text-fg">
                        {artifact.name}
                      </span>
                      {badge && <Badge color={badge.color}>{badge.label}</Badge>}
                    </span>
                    <span className="mt-0.5 block truncate text-[11px] text-fg-muted">
                      {artifactMeta(artifact)} · {formatRelative(artifact.createdAt)}
                    </span>
                    {artifact.tags.length > 0 && (
                      <span className="mt-0.5 block truncate font-mono text-[10px] text-fg-subtle">
                        {artifact.tags.map((tag) => `#${tag}`).join(' ')}
                      </span>
                    )}
                  </button>
                </li>
              )
            })}
          </ul>
        )}
      </nav>
      <div className="flex gap-2 border-t border-line px-3 py-2.5">
        <Button
          size="sm"
          variant="secondary"
          icon={Download}
          className="min-w-0 flex-1"
          disabled={artifacts.length === 0}
          title="Export the artifacts listed above"
          onClick={() => setTransfer(exportRequest(artifacts.slice(0, 500)))}
        >
          Export {artifacts.length > 0 ? Math.min(artifacts.length, 500) : ''}
        </Button>
        {can('admin') && (
          <Button
            size="sm"
            variant="secondary"
            icon={Upload}
            className="min-w-0 flex-1"
            onClick={() => setTransfer({ mode: 'import' })}
          >
            Import
          </Button>
        )}
      </div>
      <ArtifactTransferDialog request={transfer} onClose={() => setTransfer(null)} onImported={refresh} />
    </aside>
  )
}
