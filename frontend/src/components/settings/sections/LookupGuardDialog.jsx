import { useState } from 'react'
import { Button, Modal } from '../../ui/index.js'
import { guardConfirmed } from '../../../domain/enrichment.js'

/*
 * The double check before a class of data is opened for the look-ups made
 * outside playbooks: a box to tick, and the name of the class typed as it is
 * written. It is the check a playbook's screen asks before a class is opened
 * for the playbook, with the name of the class where that one has the name
 * of the playbook: there is no playbook here. The server asks for the same
 * two things, and writes who opened what in the audit log.
 */

/**
 * @param {{
 *   item: { id: string, label: string, warning: string, example: string } | null,   // null: closed
 *   destinations: string,          // where it could go: the sources that are on
 *   actor: string,
 *   onConfirm: (check: { acknowledged: true, confirmName: string }) => Promise<void>,
 *   onClose: () => void,
 * }} props
 */
// The dialog lives only while it is open, so every opening starts clean: the box unticked, the name empty.
export default function LookupGuardDialog(props) {
  return props.item ? <OpenDialog {...props} /> : null
}

function OpenDialog({ item, destinations, actor, onConfirm, onClose }) {
  const [ticked, setTicked] = useState(false)
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  const ready = guardConfirmed(item, ticked, typed) && !busy
  const submit = async (event) => {
    event.preventDefault()
    if (!ready) return
    setBusy(true)
    setError(null)
    try {
      await onConfirm({ acknowledged: true, confirmName: typed })
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={`Let ${item.label.toLowerCase()} leave Nik in the look-ups?`}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="danger" type="submit" form="form-lookup-guard" disabled={!ready}>
            Allow {item.label.toLowerCase()}
          </Button>
        </>
      }
    >
      <form id="form-lookup-guard" onSubmit={submit} className="flex flex-col gap-3 text-sm">
        <p className="border border-high-line bg-high-soft p-3 text-high-fg">{item.warning}</p>
        <p className="text-fg-muted">{item.example}</p>
        <p className="text-fg-muted">
          {destinations} This is for “Check now”, the checks in bulk and the automatic look-ups; a playbook keeps to
          what was opened for it.
        </p>
        <label className="flex items-start gap-2">
          <input
            type="checkbox"
            checked={ticked}
            onChange={(event) => setTicked(event.target.checked)}
            className="mt-1 accent-accent"
          />
          <span>These sources may hold this data.</span>
        </label>
        <label className="flex flex-col gap-1" htmlFor="lookup-guard-name">
          <span>
            I am <span className="font-mono">{actor}</span> and I take this choice: type the name of the class,{' '}
            <span className="font-mono">{item.label}</span>, to confirm.
          </span>
          <input
            id="lookup-guard-name"
            type="text"
            value={typed}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => setTyped(event.target.value)}
            className="w-full border border-line bg-canvas px-2 py-1.5 font-mono text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          />
        </label>
        <p className="text-xs text-fg-muted">This is written in the audit log, with your name.</p>
        {error && (
          <p role="alert" className="text-high-fg">
            {error}
          </p>
        )}
      </form>
    </Modal>
  )
}
