import { useEffect, useState } from 'react'
import { AlertTriangle, ScrollText, Trash2 } from 'lucide-react'
import { useItemMenu } from '../../menu/useRowMenu.js'
import { Badge, Button, DataTable, EmptyState, Wait } from '../../ui/index.js'
import { useAudit } from '../../../context/AuditContext.jsx'
import { useAuth } from '../../../context/AuthContext.jsx'
import { formatDateTime } from '../../../lib/time.js'
import AuditChainPanel from './AuditChainPanel.jsx'
import AuditForwardingForm from './AuditForwardingForm.jsx'

/*
 * Audit-log settings section: the global, cross-incident audit trail, written
 * by the server and read each time the section opens.
 *
 * The log is a chain: the panel at the top says how far it was verified and
 * walks it on demand; administrators set below it where the log is sent as it
 * is written. Nothing edits an entry. Old entries can be removed, by a
 * signed-in administrator and behind a confirmation: the chain then keeps one
 * entry that says how many went and up to which hash, so it still verifies.
 */

function actionBadgeColor(action) {
  const a = String(action ?? '').toLowerCase()
  if (a.includes('delete') || a.includes('remove') || a.includes('clear')) return 'red'
  if (a.includes('create') || a.includes('add') || a.includes('import') || a.includes('upload')) return 'emerald'
  if (a.includes('login')) return 'cyan'
  if (a.includes('update') || a.includes('edit') || a.includes('flag')) return 'amber'
  return 'slate'
}

const COLUMNS = [
  {
    key: 'time',
    label: 'Time',
    sortable: true,
    sortAccessor: (row) => Date.parse(row.at) || 0,
    className: 'whitespace-nowrap',
    render: (row) => <span className="font-mono text-xs text-fg-muted">{formatDateTime(Date.parse(row.at))}</span>,
  },
  {
    key: 'actor',
    label: 'Actor',
    sortable: true,
    className: 'whitespace-nowrap',
    render: (row) => <span className="font-medium text-fg">{row.actor || 'system'}</span>,
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
    render: (row) => <span className="text-fg-muted">{row.details || '—'}</span>,
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
  const menu = useItemMenu(null)
  const { entries, loading, error, clearAudit, refresh } = useAudit()
  const { can } = useAuth()
  const isAdmin = can('admin')
  const [confirming, setConfirming] = useState(false)
  // The chain is read again after the log was changed from this page.
  const [chainKey, setChainKey] = useState(0)

  useEffect(() => {
    refresh()
  }, [refresh])

  const handleClear = async () => {
    setConfirming(false)
    await clearAudit()
    setChainKey((key) => key + 1)
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
              : loading
                ? 'Loading…'
                : 'No entries recorded yet.'}
          </p>
          {error && (
            <p role="alert" className="mt-1 text-sm text-high">
              {error}
            </p>
          )}
        </div>
        {isAdmin && hasEntries && !confirming && (
          <Button
            variant="ghost"
            size="sm"
            icon={Trash2}
            onClick={() => setConfirming(true)}
            className="text-high hover:bg-high-soft hover:text-high"
          >
            Remove the entries…
          </Button>
        )}
      </div>

      <AuditChainPanel key={chainKey} onVerified={refresh} />
      {isAdmin && <AuditForwardingForm />}

      {confirming && (
        <div className="flex flex-wrap items-center justify-between gap-3 border border-high-line bg-high-soft px-4 py-3">
          <div className="flex items-start gap-2">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-high" aria-hidden="true" />
            <p className="text-sm text-high">
              Remove the {entries.length} audit {entries.length === 1 ? 'entry' : 'entries'}? This cannot be undone. One
              entry stays in their place: it says how many were removed, by whom, and the hash of the last, so the chain
              still verifies. While the log is forwarded, what was not sent yet stays too.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={() => setConfirming(false)}>
              Cancel
            </Button>
            <Button variant="danger" size="sm" icon={Trash2} onClick={handleClear}>
              Remove the entries
            </Button>
          </div>
        </div>
      )}

      {hasEntries ? (
        <DataTable
          columns={COLUMNS}
          data={entries}
          onRowContextMenu={(event, row) =>
            menu(event, {
              title: row.action,
              text: [row.at, row.actor, row.action, row.details].filter(Boolean).join('  '),
              copy: [{ label: 'details', text: row.details }],
              record: row,
            })
          }
          searchKeys={SEARCH_KEYS}
          searchPlaceholder="Search audit log…"
          defaultSort={{ key: 'time', dir: 'desc' }}
          emptyMessage="No entries match your search."
          rowKey={(row) => row.id}
        />
      ) : loading ? (
        <Wait>Loading the audit log…</Wait>
      ) : (
        <EmptyState
          skull
          title="No audit entries yet"
          message="Actions performed across incidents will be recorded here."
        />
      )}
    </section>
  )
}
