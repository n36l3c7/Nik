import { useEffect, useState } from 'react'
import { AlertTriangle, ScrollText, Trash2 } from 'lucide-react'
import { Badge, Button, DataTable, EmptyState, Modal } from '../ui/index.js'
import { useAudit } from '../../context/AuditContext.jsx'
import { useAuth } from '../../context/AuthContext.jsx'
import { formatDateTime } from '../../utils/time.js'

/*
 * ============================================================================
 * AUDIT LOG VIEW
 * ============================================================================
 *
 * Read-only modal that surfaces the global, cross-incident audit trail from
 * `useAudit()`. Every entry answers: who (actor), when (at), what (action),
 * the details, and which incident it belonged to.
 *
 * The whole log can be wiped, but only by an admin — that control is gated on
 * `currentUser.role === 'admin'` and guarded by an inline confirmation step so
 * the destructive action is never a single accidental click.
 */

/**
 * Pick a Badge color for an action string based on its verb, giving the table
 * a quick visual language (destructive = red, additive = emerald, etc.).
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

// Column definitions for the audit DataTable. `time` uses a numeric sort
// accessor (parsed from the ISO `at` field) so the default descending sort
// puts the most recent events first.
const COLUMNS = [
  {
    key: 'time',
    label: 'Time',
    sortable: true,
    sortAccessor: (row) => Date.parse(row.at) || 0,
    className: 'whitespace-nowrap',
    render: (row) => (
      <span className="font-mono text-xs text-slate-600 dark:text-slate-400">
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
      <span className="font-medium text-slate-700 dark:text-slate-200">
        {row.actor || 'system'}
      </span>
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
      <span className="text-slate-600 dark:text-slate-300">{row.details || '—'}</span>
    ),
  },
  {
    key: 'incidentName',
    label: 'Incident',
    className: 'whitespace-nowrap',
    render: (row) =>
      row.incidentName ? (
        <span className="text-slate-600 dark:text-slate-300">{row.incidentName}</span>
      ) : (
        <span className="text-slate-400 dark:text-slate-500">—</span>
      ),
  },
]

const SEARCH_KEYS = ['actor', 'action', 'details', 'incidentName']

export default function AuditLogView({ open, onClose }) {
  const { entries, clearAudit } = useAudit()
  const { currentUser } = useAuth()
  const isAdmin = currentUser?.role === 'admin'

  // Whether the inline "are you sure?" confirmation banner is showing.
  const [confirming, setConfirming] = useState(false)

  // Always drop back to the resting state whenever the modal is (re)opened.
  useEffect(() => {
    if (!open) setConfirming(false)
  }, [open])

  const handleClear = () => {
    clearAudit()
    setConfirming(false)
  }

  const hasEntries = entries.length > 0

  return (
    <Modal open={open} onClose={onClose} title="Audit log" maxWidth="max-w-4xl">
      <div className="space-y-4">
        {/* Header row: entry count + admin-only clear control */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-sm text-slate-500 dark:text-slate-400">
            {hasEntries
              ? `${entries.length} ${entries.length === 1 ? 'entry' : 'entries'} recorded`
              : 'No entries recorded'}
          </p>

          {isAdmin && hasEntries && !confirming && (
            <Button
              variant="ghost"
              size="sm"
              icon={Trash2}
              onClick={() => setConfirming(true)}
              className="text-red-600 hover:bg-red-50 hover:text-red-700 dark:text-red-400 dark:hover:bg-red-500/10 dark:hover:text-red-300"
            >
              Clear log
            </Button>
          )}
        </div>

        {/* Inline confirmation for the destructive clear action */}
        {confirming && (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-red-200 bg-red-50 px-4 py-3 dark:border-red-500/30 dark:bg-red-500/10">
            <div className="flex items-start gap-2">
              <AlertTriangle
                className="mt-0.5 h-4 w-4 shrink-0 text-red-600 dark:text-red-400"
                aria-hidden="true"
              />
              <p className="text-sm text-red-700 dark:text-red-300">
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

        {/* Body: table of entries, or an empty state when the log is untouched */}
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
      </div>
    </Modal>
  )
}
