import { useEffect, useState } from 'react'
import { api } from '../../services/api.js'
import { TLP_OPTIONS } from '../../domain/iocLibrary.js'
import { Button, Modal, Select } from '../ui/index.js'

/*
 * Make a list (optionally from a scope: a selection, an incident's
 * indicators, a filter) or change one: name, description, TLP, and whether an
 * incident that comes to hold one of its indicators raises an alert.
 */

const INPUT =
  'w-full border border-line bg-canvas px-2.5 py-1.5 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/**
 * @param {{
 *   request: { list?: object, scope?: object, count?: number, name?: string } | null,
 *   onClose: () => void,
 *   onSaved: (list: object, made: boolean) => void,
 * }} props
 */
export default function ListDialog({ request, onClose, onSaved }) {
  const editing = request?.list ?? null
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [tlp, setTlp] = useState('amber')
  const [watch, setWatch] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!request) return
    setName(editing?.name ?? request.name ?? '')
    setDescription(editing?.description ?? '')
    setTlp(editing?.tlp ?? 'amber')
    setWatch(editing?.watch ?? false)
    setError(null)
  }, [request, editing])

  if (!request) return null
  const save = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const body = { name: name.trim(), description: description.trim(), tlp, watch }
      const list = editing
        ? await api.patch(`/iocs/lists/${editing.id}`, body)
        : await api.post('/iocs/lists', { ...body, ...(request.scope ? { scope: request.scope } : {}) })
      onSaved(list, !editing)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal
      open
      onClose={onClose}
      title={editing ? 'Edit the list' : 'Save as a list'}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="ioc-list-form" disabled={busy || !name.trim()}>
            {editing ? 'Save' : request.count ? `Make the list (${request.count})` : 'Make the list'}
          </Button>
        </>
      }
    >
      <form id="ioc-list-form" onSubmit={save} className="space-y-3">
        <label className="block space-y-1">
          <span className="font-mono text-xs text-fg-muted">Name</span>
          <input
            autoFocus
            aria-label="List name"
            value={name}
            maxLength={120}
            onChange={(event) => setName(event.target.value)}
            className={INPUT}
          />
        </label>
        <label className="block space-y-1">
          <span className="font-mono text-xs text-fg-muted">Description</span>
          <input
            aria-label="List description"
            value={description}
            maxLength={500}
            placeholder="source, campaign, ticket…"
            onChange={(event) => setDescription(event.target.value)}
            className={INPUT}
          />
        </label>
        <Select label="Classification" value={tlp} onChange={setTlp} options={TLP_OPTIONS} />
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={watch}
            onChange={(event) => setWatch(event.target.checked)}
            className="mt-1"
          />
          <span>
            Watch this list
            <span className="block text-xs text-fg-muted">
              An alert (and the <span className="font-mono">ioc.watch_hit</span> webhook) when an incident comes to hold
              one of its indicators.
            </span>
          </span>
        </label>
        {error && (
          <p role="alert" className="font-mono text-xs text-high">
            {error}
          </p>
        )}
      </form>
    </Modal>
  )
}
