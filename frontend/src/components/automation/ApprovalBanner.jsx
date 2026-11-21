import { useState } from 'react'
import { useAutomation } from '../../context/AutomationContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { formatDateTime, formatRelative } from '../../lib/time.js'
import { Button } from '../ui/index.js'
import { useUnsavedChanges } from '../../lib/unsaved.js'

/*
 * An approval that waits: the question, what it is about, and the two
 * answers. Shown wherever the object of the run is shown (the incident), on
 * the run itself and in the list of approvals.
 *
 * An answer may carry a comment; who answered and what they wrote go to the
 * run and to the audit log. Someone else may answer first: the server says
 * so, and the banner goes away at the next reading.
 */

/** The detail of an approval: for a node that changes something outside, the action and what it is given. */
function Detail({ detail }) {
  const entries = Object.entries(detail ?? {})
  if (entries.length === 0) return null
  return (
    <dl className="grid grid-cols-[minmax(0,8rem)_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-xs">
      {entries.map(([key, value]) => (
        <div key={key} className="contents">
          <dt className="truncate font-mono text-fg-muted">{key}</dt>
          <dd className="min-w-0 whitespace-pre-wrap break-words font-mono text-fg">
            {typeof value === 'string' ? value : JSON.stringify(value, null, 1)}
          </dd>
        </div>
      ))}
    </dl>
  )
}

/**
 * @param {{
 *   approval: object,                         // GET /api/automation/approvals
 *   onOpenRun?: (runId: string) => void,      // "See the run"; left out on the run's own page
 *   onAnswered?: (approval: object) => void,
 * }} props
 */
export default function ApprovalBanner({ approval, onOpenRun, onAnswered }) {
  const { answerApproval } = useAutomation()
  const { showToast } = useToast()
  const [comment, setComment] = useState('')
  const [busy, setBusy] = useState(false)
  useUnsavedChanges(Boolean(comment.trim()), { what: 'The comment on the approval' })

  const answer = async (verdict) => {
    setBusy(true)
    try {
      const answered = await answerApproval(approval.id, verdict, comment.trim())
      showToast({ message: verdict === 'approved' ? 'Approved: the run goes on.' : 'Refused.' })
      onAnswered?.(answered)
    } catch (error) {
      showToast({ message: error.message })
      onAnswered?.(null)
    } finally {
      setBusy(false)
    }
  }

  const commentId = `approval-comment-${approval.id}`
  return (
    <section
      aria-label={`Approval asked: ${approval.question}`}
      className="flex flex-col gap-2 border border-med-line bg-med-soft px-3 py-2.5 text-sm text-fg"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p>
            <span className="font-semibold text-med-fg">Approval asked:</span> {approval.question}
          </p>
          <p className="text-xs text-fg-muted">
            {approval.playbook} · asked {formatRelative(approval.askedAt)} ·{' '}
            {approval.expiresAt
              ? `waits until ${formatDateTime(new Date(approval.expiresAt).getTime())}`
              : 'waits without limit'}
            {onOpenRun && (
              <>
                {' · '}
                <button
                  type="button"
                  onClick={() => onOpenRun(approval.runId)}
                  className="text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  see the run
                </button>
              </>
            )}
          </p>
        </div>
        <div className="flex shrink-0 gap-2">
          <Button size="sm" disabled={busy} onClick={() => answer('approved')}>
            Approve
          </Button>
          <Button size="sm" variant="secondary" disabled={busy} onClick={() => answer('refused')}>
            Refuse
          </Button>
        </div>
      </div>
      <Detail detail={approval.detail} />
      <label htmlFor={commentId} className="sr-only">
        A comment with the answer
      </label>
      <input
        id={commentId}
        type="text"
        value={comment}
        maxLength={1000}
        placeholder="A comment with the answer (optional)"
        autoComplete="off"
        onChange={(event) => setComment(event.target.value)}
        className="w-full border border-med-line bg-sunken px-2 py-1 text-xs text-fg placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      />
    </section>
  )
}
