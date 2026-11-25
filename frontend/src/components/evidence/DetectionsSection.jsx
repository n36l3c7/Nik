import { useMemo, useState } from 'react'
import { ListFilter, ShieldAlert } from 'lucide-react'
import { Button, DataTable, Select } from '../ui/index.js'
import LevelBadge from './LevelBadge.jsx'
import { LEVEL_FILTER_OPTIONS, hostsText, rulesAtLeast, tagChips, tagUrl } from '../../domain/detections.js'
import { formatDateTime } from '../../lib/time.js'

/*
 * The "Detections" part of a host page: the rules that matched records of the section, one row each,
 * the highest level first, with how many records, when, on which hosts, their ATT&CK tags and the
 * author of the rule (its licence asks for it: it is always in the row). A row opens the records the
 * rule matched (`onOpen(rule)`: the page shows its table filtered on `rule=<id>`).
 */

const NO_RULES = []

function Tags({ tags }) {
  const shown = tagChips(tags)
  if (shown.length === 0) return <span className="text-fg-muted">—</span>
  return (
    <span className="flex flex-wrap gap-1">
      {shown.map((tag) => {
        const url = tagUrl(tag)
        const look = 'border border-line bg-canvas px-1.5 py-px font-mono text-[11px]'
        return url ? (
          <a
            key={tag}
            href={url}
            target="_blank"
            rel="noreferrer noopener"
            onClick={(event) => event.stopPropagation()}
            className={`${look} text-link hover:underline`}
          >
            {tag}
          </a>
        ) : (
          <span key={tag} className={`${look} text-fg-muted`}>
            {tag}
          </span>
        )
      })}
    </span>
  )
}

/**
 * @param {{
 *   data: { rules: object[], total: number },     // `GET …/evidence/detections`
 *   loading?: boolean,
 *   error?: string,
 *   onOpen: (rule: object) => void,
 *   noun?: string,                                // what the rule matched: "events", "commands", "records"
 * }} props
 */
export default function DetectionsSection({ data, loading = false, error = '', onOpen, noun = 'records' }) {
  const [level, setLevel] = useState('')
  const rules = useMemo(() => rulesAtLeast(data?.rules ?? NO_RULES, level), [data, level])

  const columns = useMemo(
    () => [
      { key: 'level', label: 'Level', render: (row) => <LevelBadge level={row.level} /> },
      {
        key: 'title',
        label: 'Rule',
        render: (row) => (
          <div className="min-w-0">
            <p className="text-sm font-medium text-fg">{row.title}</p>
            <p className="text-xs text-fg-muted">{row.author ? `Rule by ${row.author}` : 'No author named'}</p>
          </div>
        ),
      },
      {
        key: 'count',
        label: 'Count',
        align: 'right',
        render: (row) => <span className="font-mono text-xs tabular-nums">{row.count.toLocaleString('en-US')}</span>,
      },
      {
        key: 'first',
        label: 'First',
        render: (row) => (
          <span className="whitespace-nowrap font-mono text-xs">
            {Number.isFinite(row.firstTs) ? formatDateTime(row.firstTs) : '—'}
          </span>
        ),
      },
      {
        key: 'last',
        label: 'Last',
        render: (row) => (
          <span className="whitespace-nowrap font-mono text-xs">
            {Number.isFinite(row.lastTs) ? formatDateTime(row.lastTs) : '—'}
          </span>
        ),
      },
      {
        key: 'hosts',
        label: 'Hosts',
        render: (row) => <span className="font-mono text-xs">{hostsText(row) || '—'}</span>,
      },
      { key: 'tags', label: 'ATT&CK', render: (row) => <Tags tags={row.tags} /> },
      {
        key: 'open',
        label: '',
        className: 'w-px',
        render: (row) => (
          <Button
            variant="ghost"
            size="xs"
            icon={ListFilter}
            aria-label={`Show the ${noun} that matched ${row.title}`}
            onClick={(event) => {
              event.stopPropagation()
              onOpen(row)
            }}
          >
            Show {noun}
          </Button>
        ),
      },
    ],
    [onOpen, noun],
  )

  if (error) {
    return (
      <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
        The detections could not be read: {error}
      </p>
    )
  }

  return (
    <div role="tabpanel" aria-label="Detections" className="space-y-3">
      <DataTable
        columns={columns}
        data={rules}
        rowKey={(row) => row.ruleId}
        defaultPageSize={25}
        searchKeys={['title', 'author']}
        searchPlaceholder="Search the rules…"
        onRowClick={onOpen}
        rowClassName={() => 'cursor-pointer'}
        emptyMessage={
          loading
            ? 'Reading the detections…'
            : (data?.rules?.length ?? 0) > 0
              ? 'No rule of this level matched'
              : 'No rule matched anything here. Rules run when a file is read: "Analyse again" on a file runs them again.'
        }
        toolbar={
          <div className="flex flex-wrap items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-fg-muted" aria-hidden="true" />
            <Select label="Detection" value={level} onChange={setLevel} options={LEVEL_FILTER_OPTIONS} />
          </div>
        }
      />
    </div>
  )
}
