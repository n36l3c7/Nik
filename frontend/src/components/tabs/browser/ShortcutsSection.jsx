import { useCallback, useMemo, useState } from 'react'
import { Check, Copy, ExternalLink, Flag, Zap } from 'lucide-react'
import { useRowMenu } from '../../menu/useRowMenu.js'
import { Card, DataTable, EmptyState, EvidenceLink } from '../../ui/index.js'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { formatDateTime } from '../../../lib/time.js'
import { truncate } from '../../../lib/url.js'

/*
 * "Shortcuts (Omnibox)" section of the Browser Forensics tab.
 * Shortcuts are Chrome's omnibox shortcuts: they record the text the user
 * typed in the address bar and the associated destination — a valuable
 * artifact because it reveals the user's INTENT, not just the pages visited.
 * Each row can be flagged and its URL copied on hover.
 */

/** Flag toggle button rendered in the first column of each row. */
function FlagButton({ flagged, onToggle }) {
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-label={flagged ? 'Remove flag' : 'Flag as malicious'}
      title={flagged ? 'Remove flag' : 'Flag as malicious'}
      className={[
        'p-1 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
        flagged ? 'text-accent' : 'text-fg-subtle hover:text-accent',
      ].join(' ')}
    >
      <Flag size={15} className={flagged ? 'fill-accent' : ''} />
    </button>
  )
}

/** Copy-to-clipboard button; shows on hover and flips to a check briefly. */
function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async (event) => {
    event.stopPropagation()
    if (!text) return
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    } catch {
      // Clipboard API may be unavailable (insecure context): fail silently.
    }
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label="Copy"
      title="Copy to clipboard"
      className="shrink-0 p-0.5 text-fg-muted opacity-0 transition-opacity hover:text-accent focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent group-hover:opacity-100"
    >
      {copied ? <Check size={13} className="text-accent" /> : <Copy size={13} />}
    </button>
  )
}

/**
 * @param {{ incident: object, browserId: string, profile?: object, shortcuts?: Array, meta?: object|null }} props
 */
export default function ShortcutsSection({ incident, browserId, profile = null, shortcuts = [], meta = null }) {
  const { toggleFlag } = useIncidents()
  const flags = incident.flags

  const rowMenu = useRowMenu(incident)
  /** What a row passes to toggleFlag() (the flag button and the right-click menu). */
  const flaggable = useCallback(
    (row) => ({
      key: row.id,
      browserId,
      profileId: profile?.id ?? null,
      profileName: profile?.name ?? null,
      section: 'shortcuts',
      eventType: 'shortcut',
      title: row.text || row.title || '',
      url: row.url || '',
      time: row.lastAccessTime ?? null,
    }),
    [browserId, profile?.id, profile?.name],
  )
  const columns = useMemo(
    () => [
      {
        key: 'flag',
        label: '',
        headerClassName: 'w-10',
        render: (row) => (
          <FlagButton flagged={!!flags[row.id]} onToggle={() => toggleFlag(incident.id, flaggable(row))} />
        ),
      },
      {
        key: 'text',
        label: 'Typed text',
        sortable: true,
        // Case-insensitive alphabetical sort on the typed text
        sortAccessor: (row) => (row.text ?? '').toLowerCase(),
        render: (row) => (
          <span
            className="font-mono text-[13px] font-medium text-accent"
            title="Text typed by the user in Chrome's omnibox"
          >
            “{row.text}”
          </span>
        ),
      },
      {
        key: 'title',
        label: 'Title',
        render: (row) =>
          row.title ? (
            <span className="block max-w-[28ch] truncate text-fg" title={row.title}>
              {row.title}
            </span>
          ) : (
            <span className="italic text-fg-muted">(no title)</span>
          ),
      },
      {
        key: 'url',
        label: 'URL',
        render: (row) => (
          <span className="group flex items-center gap-1.5">
            <span className="font-mono text-xs text-fg-muted" title={row.url}>
              {truncate(row.url, 60)}
            </span>
            {row.url && (
              <>
                <EvidenceLink
                  url={row.url}
                  title="Open the address… (asks first)"
                  aria-label="Open the address"
                  className="shrink-0 text-fg-muted hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  <ExternalLink size={13} />
                </EvidenceLink>
                <CopyButton text={row.url} />
              </>
            )}
          </span>
        ),
      },
      {
        key: 'hits',
        label: 'Hits',
        sortable: true,
        align: 'right',
        sortAccessor: (row) => row.hits ?? 0,
        className: 'font-mono text-xs',
        render: (row) => row.hits ?? 0,
      },
      {
        key: 'lastAccessTime',
        label: 'Last access',
        sortable: true,
        sortAccessor: (row) => row.lastAccessTime ?? 0,
        className: 'whitespace-nowrap font-mono text-xs',
        render: (row) => formatDateTime(row.lastAccessTime),
      },
    ],
    [flags, incident.id, flaggable, toggleFlag],
  )

  // Cyan highlight for flagged rows (distinct from severity colors).
  const rowClassName = (row) => (flags[row.id] ? 'bg-accent-soft border-l-2 border-l-accent-strong' : '')

  // No data: explain what Shortcuts are and how to import them.
  if (!shortcuts.length) {
    return (
      <EmptyState
        icon={Zap}
        title="No shortcuts loaded"
        message="Shortcuts are Chrome's omnibox shortcuts: they record what the user typed in the address bar and the associated destination. Import the 'Shortcuts' file (SQLite) or a JSON/CSV export."
      />
    )
  }

  return (
    <Card
      title="Shortcuts (Omnibox)"
      icon={Zap}
      actions={
        meta && (
          <span className="text-xs text-fg-muted">
            {meta.fileName} · {meta.rows} rows
          </span>
        )
      }
    >
      <DataTable
        columns={columns}
        onRowContextMenu={(event, row) => rowMenu(event, { flaggable: flaggable(row), record: row })}
        data={shortcuts}
        searchKeys={['text', 'url', 'title']}
        searchPlaceholder="Search by typed text, URL or title…"
        defaultSort={{ key: 'lastAccessTime', dir: 'desc' }}
        rowClassName={rowClassName}
        emptyMessage="No shortcut matches your search"
      />
    </Card>
  )
}
