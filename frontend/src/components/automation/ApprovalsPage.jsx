import { useCallback, useEffect, useState } from 'react'
import { useAutomation } from '../../context/AutomationContext.jsx'
import { api } from '../../services/api.js'
import { formatDateTime } from '../../lib/time.js'
import { Badge, EmptyState } from '../ui/index.js'
import ApprovalBanner from './ApprovalBanner.jsx'
import { SectionTitle } from './fields.jsx'

/*
 * The approvals: what waits for an answer, oldest first, and under it what
 * was answered lately (by whom, with what comment). Anyone who may run
 * playbooks may answer.
 */

const ANSWER_COLORS = { approved: 'emerald', refused: 'red', expired: 'slate' }

/**
 * @param {{ onOpenRun: (id: string) => void }} props
 */
export default function ApprovalsPage({ onOpenRun }) {
  const { approvals, refreshApprovals } = useAutomation()
  const [answered, setAnswered] = useState(null)

  const loadAnswered = useCallback(async () => {
    try {
      const found = await api.get('/automation/approvals?status=all&limit=50')
      setAnswered(found.approvals.filter((approval) => approval.status !== 'waiting'))
    } catch {
      setAnswered([])
    }
  }, [])
  useEffect(() => {
    refreshApprovals()
    loadAnswered()
  }, [refreshApprovals, loadAnswered])

  return (
    <div className="flex max-w-4xl flex-col gap-6 p-6">
      <section aria-label="Waiting for an answer" className="flex flex-col gap-3">
        <SectionTitle>Waiting for an answer · {approvals.length}</SectionTitle>
        {approvals.length === 0 ? (
          <EmptyState
            skull
            title="Nothing waits for an answer"
            message="A run stops here when a playbook asks a person: at an approval node, or before a node that changes something outside Nik."
          />
        ) : (
          approvals.map((approval) => (
            <ApprovalBanner key={approval.id} approval={approval} onOpenRun={onOpenRun} onAnswered={loadAnswered} />
          ))
        )}
      </section>

      {answered && answered.length > 0 && (
        <section aria-label="Answered lately" className="flex flex-col gap-3">
          <SectionTitle>Answered lately</SectionTitle>
          <ul className="flex flex-col divide-y divide-line-soft border border-line">
            {answered.map((approval) => (
              <li key={approval.id} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-3 py-2 text-sm">
                <Badge color={ANSWER_COLORS[approval.status] ?? 'slate'}>{approval.status}</Badge>
                <span className="min-w-0 flex-1">
                  {approval.question}
                  <span className="block text-xs text-fg-muted">
                    {approval.playbook}
                    {approval.answeredBy ? ` · ${approval.answeredBy}` : ''}
                    {approval.answeredAt ? ` · ${formatDateTime(Date.parse(approval.answeredAt))}` : ''}
                    {approval.comment ? ` · “${approval.comment}”` : ''}
                  </span>
                </span>
                <button
                  type="button"
                  onClick={() => onOpenRun(approval.runId)}
                  className="text-xs text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  see the run
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  )
}
