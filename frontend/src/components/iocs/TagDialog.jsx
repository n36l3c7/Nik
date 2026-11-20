import { useState } from 'react'
import { api } from '../../services/api.js'
import { parseTags } from '../../domain/iocLibrary.js'
import { Button, Modal } from '../ui/index.js'
import { useUnsavedChanges } from '../../lib/unsaved.js'

/*
 * Tags on many indicators at once: the ones selected, or everything the
 * filter keeps. Tags to add and tags to take off, in one go.
 */

const FIELD =
  'h-9 w-full border border-line bg-canvas px-3 font-mono text-sm text-fg ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/**
 * @param {{
 *   scope: object,                    // what POST /iocs/tags takes besides the tags
 *   count: number,
 *   onDone: (result: { changed: number, unchanged: number }) => void,
 *   onClose: () => void,
 * }} props
 */
export default function TagDialog({ scope, count, onDone, onClose }) {
  const [add, setAdd] = useState('')
  const [remove, setRemove] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const unsaved = useUnsavedChanges(Boolean(add.trim() || remove.trim()), { what: 'The tags being changed' })
  const adding = parseTags(add)
  const removing = parseTags(remove)
  const wrong = [...adding.wrong, ...removing.wrong]
  const ready = (adding.tags.length > 0 || removing.tags.length > 0) && wrong.length === 0

  const save = () => {
    setBusy(true)
    setError(null)
    api
      .post('/iocs/tags', { ...scope, add: adding.tags, remove: removing.tags })
      .then(onDone, (failure) => setError(failure.message))
      .finally(() => setBusy(false))
  }

  return (
    <Modal
      open
      onClose={() => unsaved.leave(onClose)}
      title={`Tags on ${count} indicator${count === 1 ? '' : 's'}`}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={save} disabled={!ready || busy}>
            {busy ? 'Saving…' : 'Save'}
          </Button>
        </>
      }
    >
      <form
        className="space-y-4 text-sm"
        onSubmit={(event) => {
          event.preventDefault()
          if (ready && !busy) save()
        }}
      >
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-fg-muted">Add these tags</span>
          <input
            type="text"
            value={add}
            placeholder="campaign-q4, c2"
            onChange={(event) => setAdd(event.target.value)}
            className={FIELD}
          />
        </label>
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-fg-muted">Take these tags off</span>
          <input type="text" value={remove} onChange={(event) => setRemove(event.target.value)} className={FIELD} />
        </label>
        <p className="text-xs text-fg-muted">
          Tags are separated by commas or spaces: letters, digits, dots, colons, - and _. An indicator keeps the tags
          that are not named here.
        </p>
        {wrong.length > 0 && (
          <p role="alert" className="text-high">
            Not a tag: {wrong.join(', ')}
          </p>
        )}
        {error && (
          <p role="alert" className="text-high">
            {error}
          </p>
        )}
      </form>
    </Modal>
  )
}
