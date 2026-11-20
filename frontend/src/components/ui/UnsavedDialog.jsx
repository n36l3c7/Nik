import { AlertCircle } from 'lucide-react'
import { canSaveAll, sentenceOf } from '../../domain/unsaved.js'
import { answer, useLeaveQuestion } from '../../lib/unsaved.js'
import Button from './Button.jsx'
import Modal from './Modal.jsx'

/*
 * The question asked before unsaved work is lost (lib/unsaved.js): it names
 * what is not saved and lets the person stay, leave without saving, or save
 * and leave where what is being edited can be saved from here. Mounted once,
 * by App; it opens above whatever is open.
 */

function Sentence({ entry }) {
  const { before, name, after } = sentenceOf(entry)
  return (
    <>
      {before}
      {name && <em className="font-semibold not-italic text-fg">{name}</em>}
      {after}
    </>
  )
}

export default function UnsavedDialog() {
  const question = useLeaveQuestion()
  if (!question) return null
  const { lost, saving, error } = question
  return (
    <Modal
      open
      front
      onClose={() => answer('stay')}
      title="Leave without saving?"
      maxWidth="max-w-md"
      footer={
        <>
          <Button variant="ghost" disabled={saving} onClick={() => answer('leave')}>
            Leave without saving
          </Button>
          {canSaveAll(lost) && (
            <Button variant="secondary" disabled={saving} onClick={() => answer('save')}>
              {saving ? 'Saving…' : 'Save and leave'}
            </Button>
          )}
          <Button autoFocus disabled={saving} onClick={() => answer('stay')}>
            Stay
          </Button>
        </>
      }
    >
      {lost.length === 1 ? (
        <p>
          <Sentence entry={lost[0]} />
        </p>
      ) : (
        <>
          <p>These have changes that are not saved:</p>
          <ul className="mt-2 list-disc space-y-1 pl-5">
            {lost.map((entry) => (
              <li key={entry.id}>
                <Sentence entry={entry} />
              </li>
            ))}
          </ul>
        </>
      )}
      <p className="mt-2 text-fg-muted">Leaving now throws the changes away.</p>
      {error && (
        <div
          role="alert"
          className="mt-3 flex items-start gap-2 border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg"
        >
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          <span>{error}</span>
        </div>
      )}
    </Modal>
  )
}
