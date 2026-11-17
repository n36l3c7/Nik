import { useState } from 'react'
import { Button, Modal } from '../ui/index.js'
import { INPUT } from './fields.jsx'

/*
 * The double check before a playbook is let reach further or send more: a box
 * to tick, and the playbook's name typed as it is written. The server asks
 * for the same two things, and writes who opened what in the audit log.
 */

/**
 * @param {{
 *   open: boolean,
 *   title: string,                 // "Let e-mail addresses leave Nik in this playbook?"
 *   warning: string,               // what is being opened, in a sentence
 *   destinations: string,          // where it could go
 *   acknowledge: string,           // the sentence next to the box
 *   confirmLabel: string,          // the button
 *   playbookName: string,
 *   actor: string,
 *   onConfirm: (check: { acknowledged: true, confirmName: string }) => Promise<void>,
 *   onClose: () => void,
 * }} props
 */
/**
 * The dialog lives only while it is open, so every opening starts clean: the box
 * unticked, the name empty. (A reset by an effect could run after a quick first click.)
 */
export default function DataGuardDialog(props) {
  return props.open ? <OpenDialog {...props} /> : null
}

function OpenDialog({
  open,
  title,
  warning,
  destinations,
  acknowledge,
  confirmLabel,
  playbookName,
  actor,
  onConfirm,
  onClose,
}) {
  const [ticked, setTicked] = useState(false)
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  const ready = ticked && typed === playbookName && !busy
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
      open={open}
      onClose={onClose}
      title={title}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="danger" type="submit" form="form-data-guard" disabled={!ready}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <form id="form-data-guard" onSubmit={submit} className="flex flex-col gap-3 text-sm">
        <p className="border border-high-line bg-high-soft p-3 text-high-fg">{warning}</p>
        <p className="text-fg-muted">{destinations}</p>
        <label className="flex items-start gap-2">
          <input
            type="checkbox"
            checked={ticked}
            onChange={(event) => setTicked(event.target.checked)}
            className="mt-1 accent-accent"
          />
          <span>{acknowledge}</span>
        </label>
        <label className="flex flex-col gap-1" htmlFor="data-guard-name">
          <span>
            I am <span className="font-mono">{actor}</span> and I take this choice: type the playbook’s name,{' '}
            <span className="font-mono">{playbookName}</span>, to confirm.
          </span>
          <input
            id="data-guard-name"
            type="text"
            value={typed}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => setTyped(event.target.value)}
            className={INPUT}
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
