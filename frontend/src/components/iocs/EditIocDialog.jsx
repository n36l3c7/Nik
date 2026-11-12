import { useEffect, useState } from 'react'
import { api } from '../../services/api.js'
import { TLP_OPTIONS } from '../../domain/iocLibrary.js'
import { Button, Modal, Select } from '../ui/index.js'

/* What an analyst writes about one indicator: tags, a note, its TLP and the
 * day after which it is no longer current. */

const INPUT =
  'w-full border border-line bg-canvas px-2.5 py-1.5 font-mono text-xs text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/** @param {{ row: object | null, onClose: () => void, onSaved: (row: object) => void }} props */
export default function EditIocDialog({ row, onClose, onSaved }) {
  const [tags, setTags] = useState('')
  const [note, setNote] = useState('')
  const [tlp, setTlp] = useState('amber')
  const [expires, setExpires] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!row) return
    setTags(row.tags.join(' '))
    setNote(row.note)
    setTlp(row.tlp ?? 'amber')
    setExpires(row.expires ?? '')
    setError(null)
  }, [row])

  if (!row) return null
  const save = async (event) => {
    event.preventDefault()
    setBusy(true)
    try {
      onSaved(
        await api.patch('/iocs/item', {
          type: row.type,
          value: row.value,
          tags: tags.split(/[\s,;]+/).filter(Boolean),
          note,
          tlp,
          ...(expires ? { expires } : { clearExpires: true }),
        }),
      )
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
      title="Edit the indicator"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="ioc-edit-form" disabled={busy}>
            Save
          </Button>
        </>
      }
    >
      <form id="ioc-edit-form" onSubmit={save} className="space-y-3">
        <p className="break-all font-mono text-xs text-fg-muted">
          {row.type} · <span className="text-fg">{row.value}</span>
        </p>
        <label className="block space-y-1">
          <span className="font-mono text-xs text-fg-muted">Tags</span>
          <input autoFocus aria-label="Tags" value={tags} onChange={(e) => setTags(e.target.value)} className={INPUT} />
        </label>
        <label className="block space-y-1">
          <span className="font-mono text-xs text-fg-muted">Note</span>
          <textarea
            aria-label="Note"
            value={note}
            maxLength={2000}
            onChange={(e) => setNote(e.target.value)}
            className={`${INPUT} h-20 resize-y`}
          />
        </label>
        <div className="flex flex-wrap items-center gap-3">
          <Select label="Classification" value={tlp} onChange={setTlp} options={TLP_OPTIONS} />
          <label className="flex items-center gap-2 text-sm">
            <span className="font-mono text-xs text-fg-muted">Expires on</span>
            <input
              type="date"
              aria-label="Expires on"
              value={expires}
              onChange={(e) => setExpires(e.target.value)}
              className={`${INPUT} w-auto`}
            />
          </label>
        </div>
        {error && (
          <p role="alert" className="font-mono text-xs text-high">
            {error}
          </p>
        )}
      </form>
    </Modal>
  )
}
