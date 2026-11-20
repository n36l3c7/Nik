import { useEffect, useState } from 'react'
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
import { Badge, Button, MicroSkull } from '../ui/index.js'
import { useItemMenu } from '../menu/useRowMenu.js'
import { useAuth } from '../../context/AuthContext.jsx'
import QueryInput from '../ui/QueryInput.jsx'
import { useQuerySchema } from '../../services/querySchema.js'
import { writeValue } from '../../domain/query/complete.js'
import { conditionOn, withCondition } from '../../domain/query/builder.js'
import ArtifactTransferDialog from './ArtifactTransferDialog.jsx'
import { exportRequest } from '../../domain/artifactExpiry.js'
import HidePanel from '../layout/HidePanel.jsx'

/*
 * The artifacts panel of the sidebar: files, e-mails and captures analysed on
 * their own or in incidents, and scanned addresses, for the whole team, newest first. The filter
 * is a query read by the server ("mine" writes its condition into it); the kind chips count
 * what the query keeps of each kind.
 */

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
              openArtifact((await analyseAs(artifact.id, action.as)).id)
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
  const total = ARTIFACT_KINDS.reduce((sum, kind) => sum + (counts[kind.id] ?? 0), 0)

  return (
    <aside
      aria-label="Artifacts panel"
      style={{ width }}
      className="flex h-full shrink-0 flex-col border-r border-line bg-sunken"
    >
      {/* Three things share the width of the panel: the title is set tight so its count is not cut. */}
      <div className="flex items-center gap-1.5 border-b border-line px-3 py-3">
        <p className="min-w-0 flex-1 truncate font-mono text-[10px] text-fg-muted">ARTIFACTS · {total}</p>
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

      <nav aria-label="Artifacts" className="flex-1 overflow-y-auto">
        {error ? (
          <p role="alert" className="px-3 py-3 font-mono text-xs text-high">
            {error}
          </p>
        ) : artifacts.length === 0 ? (
          <div className="flex flex-col items-center gap-2 px-4 py-8 text-center">
            {loading ? (
              <MicroSkull className="text-lg text-fg-muted" />
            ) : (
              <Boxes className="h-6 w-6 text-fg-subtle" aria-hidden="true" />
            )}
            <p className="text-sm text-fg-muted">
              {loading
                ? 'Loading…'
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
              return (
                <li
                  key={artifact.id}
                  className="border-b border-line-soft"
                  onContextMenu={(event) => artifactMenu(event, artifact)}
                >
                  <button
                    type="button"
                    onClick={() => openArtifact(artifact.id)}
                    aria-current={active ? 'true' : undefined}
                    className={[
                      'w-full px-3 py-2 text-left transition-colors',
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
