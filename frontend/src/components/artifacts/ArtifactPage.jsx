import { Suspense, useEffect, useMemo, useState } from 'react'
import { AlertTriangle, Boxes, FolderOpen, FolderPlus, Link2, Plus, Tag, Trash2, X } from 'lucide-react'
import { useArtifacts } from '../../context/ArtifactContext.jsx'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { getTabById } from '../../config/tabs.js'
import { artifactKind, parseTags, standaloneIncident, verdictBadge } from '../../domain/artifactRegistry.js'
import { formatDateTime, anyToMs } from '../../lib/time.js'
import { AsciiSkull, Badge, Button, EmptyState, ErrorBoundary, Modal } from '../ui/index.js'
import { KIND_ICONS } from './ArtifactsPanel.jsx'
import { useItemMenu } from '../menu/useRowMenu.js'

/*
 * ============================================================================
 * ARTIFACT PAGE — one file, e-mail or capture, opened on its own
 * ============================================================================
 *
 * The header says what the artifact is, which incidents reference it, where
 * it comes from and what was taken out of it, and holds the actions (link to
 * an incident, new incident from it, tags, delete). Below, the same analysis
 * tab an incident uses (Malware, Mail or Network Analysis) shows this one
 * artifact through a stand-in incident (see standaloneIncident()).
 */

const RELATION_LABELS = { attachment: 'attachment', extracted: 'extracted object', session: 'browser session' }

function Chip({ children, onRemove, removeLabel, onClick, onMenu }) {
  return (
    <span
      onContextMenu={onMenu}
      className="inline-flex items-center border border-line bg-canvas font-mono text-xs text-fg"
    >
      {onClick ? (
        <button
          type="button"
          onClick={onClick}
          className="px-2 py-0.5 hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {children}
        </button>
      ) : (
        <span className="px-2 py-0.5">{children}</span>
      )}
      {onRemove && (
        <button
          type="button"
          aria-label={removeLabel}
          title={removeLabel}
          onClick={onRemove}
          className="border-l border-line px-1 py-0.5 text-fg-muted hover:bg-high-soft hover:text-high focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <X className="h-3 w-3" aria-hidden="true" />
        </button>
      )}
    </span>
  )
}

function Row({ label, children }) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="w-20 shrink-0 font-mono text-[11px] tracking-wider text-fg-muted">{label}</span>
      {children}
    </div>
  )
}

/**
 * @param {{
 *   onOpenIncident: (id: string) => void,            // open a linked incident
 *   onNewIncident: (artifact: object) => void,       // create an incident and link this artifact
 * }} props
 */
export default function ArtifactPage({ onOpenIncident, onNewIncident }) {
  const { current, currentId, currentError, openArtifact, closeArtifact, link, unlink, setTags, remove } =
    useArtifacts()
  const { incidents, activeIncidentId, retryActiveIncident } = useIncidents()
  const { showToast } = useToast()
  const { setFilters, filters } = useArtifacts()
  const menu = useItemMenu(null)

  const [linkOpen, setLinkOpen] = useState(false)
  const [linkTarget, setLinkTarget] = useState('')
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [tagsDraft, setTagsDraft] = useState(null) // null = not editing
  const [busy, setBusy] = useState(false)
  const [reference, setReference] = useState(null) // a capture's live reference

  useEffect(() => {
    setReference(null)
    setTagsDraft(null)
  }, [currentId])

  const artifact = current?.id === currentId ? current : null
  const incident = useMemo(() => (artifact ? standaloneIncident(artifact, reference) : null), [artifact, reference])

  if (currentError) {
    return (
      <div className="flex h-full items-center justify-center">
        <EmptyState
          illustration={<AsciiSkull preset="medium" eyes="x" tone="muted" />}
          title="Unable to open the artifact"
          message={currentError}
          action={<Button onClick={closeArtifact}>Close</Button>}
        />
      </div>
    )
  }
  if (!artifact) {
    return (
      <div aria-busy="true" className="flex flex-col items-center justify-center gap-4 py-16">
        <AsciiSkull preset="medium" />
        <p role="status" className="font-mono text-sm text-fg-muted">
          Loading the artifact…
        </p>
      </div>
    )
  }

  const kind = artifactKind(artifact.kind)
  const Icon = KIND_ICONS[artifact.kind] ?? Boxes
  const badge = verdictBadge(artifact)
  const TabComponent = getTabById(kind.tab).component
  const linkedIds = new Set(artifact.incidents.map((i) => i.id))
  const linkable = incidents.filter((i) => !linkedIds.has(i.id))
  // A capture belongs to one incident at most.
  const canLink = artifact.kind !== 'pcap' || artifact.incidents.length === 0

  const run = async (work, failure) => {
    setBusy(true)
    try {
      await work()
    } catch (err) {
      showToast({ message: `${failure}: ${err.message}` })
    } finally {
      setBusy(false)
    }
  }

  const relatedMenu = (event, item) =>
    menu(event, {
      title: item.name,
      copy: [{ label: 'name', text: item.name }],
      actions: [{ label: 'Open', icon: FolderOpen, onSelect: () => openArtifact(item.id) }],
    })

  const handleLink = () =>
    run(async () => {
      await link(artifact.id, linkTarget)
      if (linkTarget === activeIncidentId) retryActiveIncident()
      setLinkOpen(false)
      const name = incidents.find((i) => i.id === linkTarget)?.name ?? 'the incident'
      showToast({ message: `Linked to ${name}.`, action: { label: 'Open', run: () => onOpenIncident(linkTarget) } })
    }, 'Link')

  const handleUnlink = (target) =>
    run(async () => {
      await unlink(artifact.id, target.id)
      if (target.id === activeIncidentId) retryActiveIncident()
      showToast({ message: `Removed from ${target.name}. The artifact stays.` })
    }, 'Unlink')

  const handleTags = (event) => {
    event.preventDefault()
    run(async () => {
      await setTags(artifact.id, parseTags(tagsDraft))
      setTagsDraft(null)
    }, 'Tags')
  }

  const handleDelete = () =>
    run(async () => {
      const affected = artifact.incidents.some((i) => i.id === activeIncidentId)
      await remove(artifact.id)
      if (affected) retryActiveIncident()
      setDeleteOpen(false)
      showToast({ message: `${artifact.name} deleted.` })
    }, 'Delete')

  return (
    <div className="space-y-4">
      <section aria-label="Artifact" className="border border-line bg-panel">
        <div className="flex flex-wrap items-center gap-3 border-b border-line px-4 py-3">
          <Icon className="h-5 w-5 shrink-0 text-accent" aria-hidden="true" />
          <div className="min-w-0 flex-1">
            <h1 className="truncate font-mono text-base font-semibold text-fg">{artifact.name}</h1>
            <p className="truncate text-xs text-fg-muted">
              {kind.label} artifact{artifact.detail ? ` · ${artifact.detail}` : ''} · added{' '}
              {formatDateTime(anyToMs(artifact.createdAt))} by {artifact.createdBy || 'unknown'}
            </p>
          </div>
          {badge && <Badge color={badge.color}>{badge.label}</Badge>}
          <Button
            variant="secondary"
            size="sm"
            icon={Link2}
            disabled={!canLink || linkable.length === 0}
            title={
              !canLink
                ? 'A capture belongs to one incident: remove it from that incident first'
                : linkable.length === 0
                  ? 'No other incident to link to'
                  : undefined
            }
            onClick={() => {
              setLinkTarget(linkable[0]?.id ?? '')
              setLinkOpen(true)
            }}
          >
            Link to incident
          </Button>
          <Button size="sm" icon={FolderPlus} disabled={!canLink} onClick={() => onNewIncident(artifact)}>
            New incident from this
          </Button>
          <Button variant="ghost" size="sm" icon={Trash2} onClick={() => setDeleteOpen(true)}>
            Delete
          </Button>
        </div>

        <div className="space-y-2 px-4 py-3">
          <Row label="INCIDENTS">
            {artifact.incidents.length === 0 ? (
              <span className="text-xs text-fg-muted">Not linked to an incident.</span>
            ) : (
              artifact.incidents.map((item) => (
                <Chip
                  key={item.id}
                  onClick={() => onOpenIncident(item.id)}
                  onRemove={busy ? undefined : () => handleUnlink(item)}
                  removeLabel={`Remove from ${item.name}`}
                  onMenu={(event) =>
                    menu(event, {
                      title: item.name,
                      copy: [{ label: 'name', text: item.name }],
                      actions: [
                        { label: 'Open the incident', icon: FolderOpen, onSelect: () => onOpenIncident(item.id) },
                      ],
                      danger: [
                        { label: 'Remove from this incident', icon: Trash2, onSelect: () => handleUnlink(item) },
                      ],
                    })
                  }
                >
                  {item.name}
                </Chip>
              ))
            )}
          </Row>

          <Row label="TAGS">
            {tagsDraft === null ? (
              <>
                {artifact.tags.map((tag) => (
                  <Chip
                    key={tag}
                    onMenu={(event) =>
                      menu(event, {
                        title: `#${tag}`,
                        copy: [{ label: 'tag', text: tag }],
                        actions: [
                          {
                            label: 'Show the artifacts with this tag',
                            icon: Tag,
                            onSelect: () => setFilters({ ...filters, q: tag }),
                          },
                        ],
                        danger: [
                          {
                            label: 'Remove the tag',
                            icon: Trash2,
                            onSelect: () =>
                              run(
                                () =>
                                  setTags(
                                    artifact.id,
                                    artifact.tags.filter((item) => item !== tag),
                                  ),
                                'Tags',
                              ),
                          },
                        ],
                      })
                    }
                  >
                    #{tag}
                  </Chip>
                ))}
                <Button variant="ghost" size="xs" icon={Tag} onClick={() => setTagsDraft(artifact.tags.join(' '))}>
                  {artifact.tags.length ? 'Edit tags' : 'Add tags'}
                </Button>
              </>
            ) : (
              <form onSubmit={handleTags} className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
                <input
                  autoFocus
                  aria-label="Tags"
                  value={tagsDraft}
                  onChange={(event) => setTagsDraft(event.target.value)}
                  placeholder="emotet campaign:q4 customer-x"
                  className="h-7 min-w-0 flex-1 border border-line bg-canvas px-2 font-mono text-xs text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                />
                <Button type="submit" size="xs" disabled={busy}>
                  Save
                </Button>
                <Button type="button" variant="ghost" size="xs" onClick={() => setTagsDraft(null)}>
                  Cancel
                </Button>
              </form>
            )}
          </Row>

          {(artifact.parents.length > 0 || artifact.children.length > 0) && (
            <Row label="RELATED">
              {artifact.parents.map((item) => (
                <Chip key={`p-${item.id}`} onClick={() => openArtifact(item.id)} onMenu={(e) => relatedMenu(e, item)}>
                  {RELATION_LABELS[item.relation] ?? item.relation} of {item.kind} “{item.name}”
                </Chip>
              ))}
              {artifact.children.map((item) => (
                <Chip key={`c-${item.id}`} onClick={() => openArtifact(item.id)} onMenu={(e) => relatedMenu(e, item)}>
                  {RELATION_LABELS[item.relation] ?? item.relation}: {item.name}
                </Chip>
              ))}
            </Row>
          )}
        </div>
      </section>

      <Suspense
        fallback={
          <div aria-busy="true" className="flex flex-col items-center justify-center gap-4 py-16">
            <AsciiSkull preset="medium" />
            <p role="status" className="font-mono text-sm text-fg-muted">
              Loading…
            </p>
          </div>
        }
      >
        <ErrorBoundary resetKey={artifact.id}>
          <TabComponent key={artifact.id} incident={incident} onReference={setReference} />
        </ErrorBoundary>
      </Suspense>

      <Modal
        open={linkOpen}
        onClose={() => setLinkOpen(false)}
        title="Link to incident"
        footer={
          <>
            <Button variant="secondary" onClick={() => setLinkOpen(false)}>
              Cancel
            </Button>
            <Button icon={Plus} disabled={!linkTarget || busy} onClick={handleLink}>
              Link
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="text-sm text-fg-muted">
            The artifact appears in the incident's {getTabById(kind.tab).label} tab, with its indicators, on the
            timeline and in the report.
            {artifact.kind === 'pcap' ? ' A capture belongs to one incident at most.' : ''}
          </p>
          <label htmlFor="artifact-link-incident" className="block space-y-1.5">
            <span className="block font-mono text-xs text-fg-muted">Incident</span>
            <select
              id="artifact-link-incident"
              value={linkTarget}
              onChange={(event) => setLinkTarget(event.target.value)}
              className="w-full border border-line bg-canvas px-3 py-2 text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              {linkable.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))}
            </select>
          </label>
        </div>
      </Modal>

      <Modal
        open={deleteOpen}
        onClose={() => setDeleteOpen(false)}
        title="Delete artifact"
        footer={
          <>
            <Button variant="secondary" onClick={() => setDeleteOpen(false)}>
              Cancel
            </Button>
            <Button variant="danger" icon={Trash2} disabled={busy} onClick={handleDelete}>
              Delete permanently
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="text-sm text-fg">
            You are about to delete <strong className="font-mono">«{artifact.name}»</strong>: its file and its analyses.
          </p>
          <p className="flex items-start gap-2 border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            {artifact.incidents.length > 0
              ? `It is also removed from ${artifact.incidents.map((i) => i.name).join(', ')}. This cannot be undone.`
              : 'This cannot be undone.'}
          </p>
        </div>
      </Modal>
    </div>
  )
}
