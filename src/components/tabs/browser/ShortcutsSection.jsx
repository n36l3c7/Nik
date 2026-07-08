import { useMemo, useState } from 'react'
import { Check, Copy, ExternalLink, Flag, Zap } from 'lucide-react'
import { Card, DataTable, EmptyState } from '../../ui/index.js'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { formatDateTime } from '../../../utils/time.js'
import { truncate } from '../../../utils/url.js'

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
 * @param {{ incident: object, browserId: string, shortcuts?: Array, meta?: object|null }} props
 */
export default function ShortcutsSection({ incident, browserId, shortcuts = [], meta = null }) {
  const { toggleFlag } = useIncidents()
  const flags = incident.flags

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
                section: 'shortcuts',
                eventType: 'shortcut',
                title: row.text || row.title || '',
                url: row.url || '',
                time: row.lastAccessTime ?? null,
              })
            }
          />
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
            className="font-mono text-[13px] font-medium text-cyan-700 dark:text-cyan-300"
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
            <span
              className="block max-w-[28ch] truncate text-slate-700 dark:text-slate-200"
              title={row.title}
            >
              {row.title}
            </span>
          ) : (
            <span className="italic text-slate-400 dark:text-slate-500">(no title)</span>
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
              {truncate(row.url, 60)}
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
    [flags, incident.id, browserId, toggleFlag],
  )

  // Cyan highlight for flagged rows (distinct from severity colors).
  const rowClassName = (row) =>
    flags[row.id]
      ? 'bg-cyan-500/5 dark:bg-cyan-500/10 border-l-2 border-l-cyan-500'
      : ''

  // No data: explain what Shortcuts are and how to import them.
  if (!shortcuts.length) {
    return (
      <EmptyState
        icon={Zap}
        title="No shortcuts loaded"
        message="Shortcuts are Chrome's omnibox shortcuts: they record what the user typed in the address bar and the associated destination. Import the 'Shortcuts' file (SQLite) or a JSON/CSV export, or use the demo data."
      />
    )
  }

  return (
    <Card
      title="Shortcuts (Omnibox)"
      icon={Zap}
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
