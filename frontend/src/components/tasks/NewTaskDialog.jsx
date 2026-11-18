import { useId, useState } from 'react'
import { api } from '../../services/api.js'
import { Button, Modal } from '../ui/index.js'
import Assign from './Assign.jsx'

/*
 * A task added to an incident by hand: what to do, for whom, by when.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const LABEL = 'text-xs font-medium text-fg-muted'

/**
 * @param {{
 *   incidentId: string,
 *   onClose: () => void,
 *   onAdded: (task: object) => void,
 * }} props
 */
export default function NewTaskDialog({ incidentId, onClose, onAdded }) {
  const id = useId()
  const [title, setTitle] = useState('')
  const [instructions, setInstructions] = useState('')
  const [assignee, setAssignee] = useState({ owner: true })
  const [due, setDue] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  const add = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const task = await api.post(`/incidents/${encodeURIComponent(incidentId)}/tasks`, {
        title: title.trim(),
        instructions,
        assignee,
        due: due.trim() || null,
      })
      onAdded(task)
    } catch (failure) {
      setError(failure.message)
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="Add a task"
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button type="submit" form={`${id}-form`} size="sm" disabled={busy || !title.trim()}>
            Add the task
          </Button>
        </>
      }
    >
      <form id={`${id}-form`} onSubmit={add} className="flex flex-col gap-3">
        <div className="flex flex-col gap-1">
          <label htmlFor={`${id}-title`} className={LABEL}>
            What to do *
          </label>
          <input
            id={`${id}-title`}
            type="text"
            value={title}
            maxLength={300}
            autoComplete="off"
            autoFocus
            onChange={(event) => setTitle(event.target.value)}
            className={INPUT}
          />
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor={`${id}-instructions`} className={LABEL}>
            Instructions
          </label>
          <textarea
            id={`${id}-instructions`}
            rows={4}
            value={instructions}
            maxLength={20000}
            placeholder="Markdown: **bold**, lists, links."
            onChange={(event) => setInstructions(event.target.value)}
            className={INPUT}
          />
        </div>
        <Assign value={assignee} onChange={setAssignee} disabled={busy} />
        <div className="flex flex-col gap-1">
          <label htmlFor={`${id}-due`} className={LABEL}>
            Due in
          </label>
          <input
            id={`${id}-due`}
            type="text"
            value={due}
            autoComplete="off"
            placeholder="30m, 2h, 3d — empty for no due time"
            onChange={(event) => setDue(event.target.value)}
            className={`${INPUT} font-mono`}
          />
        </div>
        {error && (
          <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
            {error}
          </p>
        )}
      </form>
    </Modal>
  )
}
