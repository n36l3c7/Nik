import { useState } from 'react'
import { AlertTriangle, ScrollText, Trash2 } from 'lucide-react'
import { Badge, Button, DataTable, EmptyState } from '../../ui/index.js'
import { useAudit } from '../../../context/AuditContext.jsx'
import { useAuth } from '../../../context/AuthContext.jsx'
import { formatDateTime } from '../../../utils/time.js'

/*
 * Audit-log settings section: the global, cross-incident audit trail. Ported
 * from the old standalone AuditLogView modal. The whole log can be wiped, but
 * only by an admin and behind an inline confirmation.
 */

function actionBadgeColor(action) {
  const a = String(action ?? '').toLowerCase()
  if (a.includes('delete') || a.includes('remove') || a.includes('clear')) return 'red'
  if (a.includes('create') || a.includes('add') || a.includes('import') || a.includes('upload'))
    return 'emerald'
  if (a.includes('login')) return 'cyan'
  if (a.includes('update') || a.includes('edit') || a.includes('flag') || a.includes('demo'))
    return 'amber'
  return 'slate'
}

const COLUMNS = [
  {
    key: 'time',
    label: 'Time',
    sortable: true,
    sortAccessor: (row) => Date.parse(row.at) || 0,
    className: 'whitespace-nowrap',
    render: (row) => (
      <span className="font-mono text-xs text-fg-muted">
        {formatDateTime(Date.parse(row.at))}
      </span>
    ),
  },
  {
    key: 'actor',
    label: 'Actor',
    sortable: true,
    className: 'whitespace-nowrap',
    render: (row) => (
      <span className="font-medium text-fg">{row.actor || 'system'}</span>
    ),
  },
  {
    key: 'action',
    label: 'Action',
    sortable: true,
    className: 'whitespace-nowrap',
    render: (row) => (
      <Badge color={actionBadgeColor(row.action)}>
        <span className="font-mono">{row.action || '—'}</span>
      </Badge>
    ),
  },
  {
    key: 'details',
    label: 'Details',
    render: (row) => (
      <span className="text-fg-muted">{row.details || '—'}</span>
    ),
  },
  {
    key: 'incidentName',
    label: 'Incident',
    className: 'whitespace-nowrap',
    render: (row) =>
      row.incidentName ? (
        <span className="text-fg-muted">{row.incidentName}</span>
      ) : (
        <span className="text-fg-muted">—</span>
      ),
  },
]

const SEARCH_KEYS = ['actor', 'action', 'details', 'incidentName']

export default function AuditLogSection() {
  const { entries, clearAudit } = useAudit()
  const { currentUser } = useAuth()
  const isAdmin = currentUser?.role === 'admin'
  const [confirming, setConfirming] = useState(false)

  const handleClear = () => {
    clearAudit()
    setConfirming(false)
  }

  const hasEntries = entries.length > 0

  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <ScrollText className="h-5 w-5 text-accent" />
            <h2 className="text-base font-semibold text-fg">Audit log</h2>
          </div>
          <p className="mt-1 text-sm text-fg-muted">
            {hasEntries
              ? `${entries.length} ${entries.length === 1 ? 'entry' : 'entries'} recorded across all incidents.`
              : 'No entries recorded yet.'}
          </p>
        </div>
        {isAdmin && hasEntries && !confirming && (
          <Button
            variant="ghost"
            size="sm"
            icon={Trash2}
            onClick={() => setConfirming(true)}
            className="text-high hover:bg-high-soft hover:text-high"
          >
            Clear log
          </Button>
        )}
      </div>

      {confirming && (
        <div className="flex flex-wrap items-center justify-between gap-3 border border-high-line bg-high-soft px-4 py-3">
          <div className="flex items-start gap-2">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-high" aria-hidden="true" />
            <p className="text-sm text-high">
              Permanently delete all {entries.length} audit{' '}
              {entries.length === 1 ? 'entry' : 'entries'}? This cannot be undone.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={() => setConfirming(false)}>
              Cancel
            </Button>
            <Button variant="danger" size="sm" icon={Trash2} onClick={handleClear}>
              Clear log
            </Button>
          </div>
        </div>
      )}

      {hasEntries ? (
        <DataTable
          columns={COLUMNS}
          data={entries}
          searchKeys={SEARCH_KEYS}
          searchPlaceholder="Search audit log…"
          defaultSort={{ key: 'time', dir: 'desc' }}
          emptyMessage="No entries match your search."
          rowKey={(row) => row.id}
        />
      ) : (
        <EmptyState
          icon={ScrollText}
          title="No audit entries yet."
          message="Actions performed across incidents will be recorded here."
        />
      )}
    </section>
  )
}
