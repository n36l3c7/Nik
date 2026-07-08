import { useMemo, useState } from 'react'
import { Bookmark, Check, Copy, ExternalLink, Flag, Folder } from 'lucide-react'
import { Badge, Card, DataTable, EmptyState } from '../../ui/index.js'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { formatDateTime } from '../../../utils/time.js'
import { truncate } from '../../../utils/url.js'

/*
 * "Bookmarks" section of the Browser Forensics tab.
 * Shows the imported bookmarks (Chrome's native JSON or a flat JSON/CSV
 * export) in a searchable, sortable DataTable. Each row can be flagged as
 * part of the malicious activity, and its URL can be copied on hover.
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
        'rounded p-1 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500',
        flagged
          ? 'text-cyan-600 dark:text-cyan-400'
          : 'text-slate-300 hover:text-cyan-600 dark:text-slate-600 dark:hover:text-cyan-400',
      ].join(' ')}
    >
      <Flag size={15} className={flagged ? 'fill-cyan-500 dark:fill-cyan-400' : ''} />
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
      className="shrink-0 rounded p-0.5 text-slate-400 opacity-0 transition-opacity hover:text-cyan-600 focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 group-hover:opacity-100 dark:text-slate-500 dark:hover:text-cyan-400"
    >
      {copied ? (
        <Check size={13} className="text-emerald-500 dark:text-emerald-400" />
      ) : (
        <Copy size={13} />
      )}
    </button>
  )
}

/**
 * @param {{ incident: object, browserId: string, bookmarks?: Array, meta?: object|null }} props
 */
export default function BookmarksSection({ incident, browserId, bookmarks = [], meta = null }) {
  const { toggleFlag } = useIncidents()
  const flags = incident.flags

  // Columns depend on the current flags/incident, so build them per render
  // (memoized on the pieces that actually influence the flag column).
  const columns = useMemo(
    () => [
      {
        key: 'flag',
        label: '',
        headerClassName: 'w-10',
        render: (row) => (
          <FlagButton
            flagged={!!flags[row.id]}
            onToggle={() =>
              toggleFlag(incident.id, {
                key: row.id,
                browserId,
                section: 'bookmarks',
                eventType: 'bookmark',
                title: row.name || '',
                url: row.url || '',
                time: row.dateAdded ?? null,
              })
            }
          />
        ),
      },
      {
        key: 'name',
        label: 'Name',
        sortable: true,
        // Case-insensitive alphabetical sort on the name
        sortAccessor: (row) => (row.name ?? '').toLowerCase(),
        render: (row) => (
          <span className="flex min-w-0 items-center gap-2">
            <Bookmark size={14} className="shrink-0 text-cyan-600 dark:text-cyan-400" />
            {row.name ? (
              <span
                className="truncate font-medium text-slate-800 dark:text-slate-100"
                title={row.name}
              >
                {row.name}
              </span>
            ) : (
              <span className="italic text-slate-400 dark:text-slate-500">(no name)</span>
            )}
          </span>
        ),
      },
      {
        key: 'url',
        label: 'URL',
        render: (row) => (
          <span className="group flex items-center gap-1.5">
            <span
              className="font-mono text-xs text-slate-600 dark:text-slate-300"
              title={row.url}
            >
              {truncate(row.url, 70)}
            </span>
            {row.url && (
              <>
                <a
                  href={row.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  title="Open the URL in a new tab"
                  aria-label="Open the URL in a new tab"
                  className="shrink-0 rounded text-slate-400 hover:text-cyan-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 dark:hover:text-cyan-400"
                >
                  <ExternalLink size={13} />
                </a>
                <CopyButton text={row.url} />
              </>
            )}
          </span>
        ),
      },
      {
        key: 'folder',
        label: 'Folder',
        render: (row) =>
          row.folder ? (
            <Badge color="slate" title={row.folder}>
              <span className="inline-flex items-center gap-1">
                <Folder size={11} className="shrink-0" />
                {truncate(row.folder, 42)}
              </span>
            </Badge>
          ) : (
            <span className="text-slate-400 dark:text-slate-500">—</span>
          ),
      },
      {
        key: 'dateAdded',
        label: 'Date added',
        sortable: true,
        // dateAdded can be null: treat it as 0 for sorting
        sortAccessor: (row) => row.dateAdded ?? 0,
        className: 'whitespace-nowrap font-mono text-xs',
        render: (row) => formatDateTime(row.dateAdded),
      },
    ],
    [flags, incident.id, browserId, toggleFlag],
  )

  // Cyan highlight for flagged rows (distinct from severity colors).
  const rowClassName = (row) =>
    flags[row.id]
      ? 'bg-cyan-500/5 dark:bg-cyan-500/10 border-l-2 border-l-cyan-500'
      : ''

  // No data: invite the user to import a file or load demo data.
  if (!bookmarks.length) {
    return (
      <EmptyState
        icon={Bookmark}
        title="No bookmarks loaded"
        message="Import Chrome's 'Bookmarks' file (JSON) or a JSON/CSV export from the 'Data sources' card, or use the demo data."
      />
    )
  }

  return (
    <Card
      title="Bookmarks"
      icon={Bookmark}
      actions={
        meta && (
          <span className="text-xs text-slate-500 dark:text-slate-400">
            {meta.fileName} · {meta.rows} rows
          </span>
        )
      }
    >
      <DataTable
        columns={columns}
        data={bookmarks}
        searchKeys={['name', 'url', 'folder']}
        searchPlaceholder="Search by name, URL or folder…"
        defaultSort={{ key: 'name', dir: 'asc' }}
        rowClassName={rowClassName}
        emptyMessage="No bookmark matches your search"
      />
    </Card>
  )
}
