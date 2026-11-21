import { useState } from 'react'
import { useToast } from '../../context/ToastContext.jsx'
import { api } from '../../services/api.js'
import { ANSWERS, restartLines } from '../../domain/restarts.js'
import { formatDateTime } from '../../lib/time.js'
import { Button } from '../ui/index.js'

/*
 * A step a restart interrupted: the worker stopped after the step began a
 * call that changes something in another system (it isolates a host, sends a
 * mail, opens a ticket) and before its answer was kept. Nik does not know
 * whether the call was made and does not make it twice by guessing: the run
 * waits here until a person who can look at the other system says which of
 * the three it is. Who answered is kept on the step and in the audit log.
 * Someone else may answer first: the server says so, and the banner goes at
 * the next reading.
 */

const DONE = {
  happened: 'Taken as done: the run goes on.',
  again: 'The step is done again.',
  stop: 'The run was stopped.',
}

/**
 * @param {{
 *   runId: string,
 *   step: object,            // a step of GET /api/automation/runs/<id> whose status is "interrupted"
 *   name: string,            // the name of its node
 *   sent?: object | null,    // what the step was about to send, when the run kept it
 *   onAnswered?: () => void,
 * }} props
 */
export default function InterruptedBanner({ runId, step, name, sent, onAnswered }) {
  const { showToast } = useToast()
  const [busy, setBusy] = useState('')
  const since = restartLines(step.restarts, formatDateTime).at(0)

  const say = async (answer) => {
    setBusy(answer)
    try {
      await api.post(`/automation/runs/${encodeURIComponent(runId)}/steps/${encodeURIComponent(step.id)}/resolve`, {
        answer,
      })
      showToast({ message: DONE[answer] })
    } catch (error) {
      showToast({ message: error.message })
    } finally {
      setBusy('')
      onAnswered?.()
    }
  }

  return (
    <section
      aria-label={`Interrupted by a restart: ${name}`}
      className="flex flex-col gap-2 border border-med-line bg-med-soft px-3 py-2.5 text-sm text-fg"
    >
      <div className="min-w-0">
        <p>
          <span className="font-semibold text-med-fg">Interrupted by a restart:</span> “{name}” had begun when the
          worker stopped, and it is not known whether it happened.
        </p>
        <p className="text-xs text-fg-muted">
          {since ? `${since}. ` : ''}Nik does not do it twice by guessing. Look at the other system, then say which it
          is.
        </p>
      </div>
      {sent ? (
        <pre className="max-h-32 overflow-auto border border-med-line bg-sunken p-2 font-mono text-xs text-fg">
          {JSON.stringify(sent, null, 1)}
        </pre>
      ) : null}
      <div role="group" aria-label={`What happened to ${name}`} className="flex flex-wrap gap-2">
        {ANSWERS.map((item) => (
          <Button
            key={item.answer}
            size="sm"
            variant={item.answer === 'happened' ? 'primary' : item.answer === 'stop' ? 'danger' : 'secondary'}
            title={item.hint}
            disabled={Boolean(busy)}
            waiting={busy === item.answer}
            onClick={() => say(item.answer)}
          >
            {item.label}
          </Button>
        ))}
      </div>
    </section>
  )
}
