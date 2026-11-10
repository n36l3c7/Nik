import { useEffect, useMemo, useState } from 'react'
import { Modal } from '../../ui/index.js'
import { api } from '../../../services/api.js'
import { formatOffset, hexRows } from '../../../utils/mail.js'
import { base64Text, fromBase64 } from '../../../utils/network.js'

/*
 * Follow Stream, as in Wireshark: the conversation of a TCP, UDP, HTTP or TLS
 * stream, client data in red, server data in blue, as text (ASCII) or hex.
 */

const MODES = [
  { id: 'ascii', label: 'ASCII' },
  { id: 'hex', label: 'Hex dump' },
]

export default function FollowStream({ captureId, target, onClose }) {
  const [state, setState] = useState({ loading: true })
  const [mode, setMode] = useState('ascii')

  useEffect(() => {
    if (!target) return undefined
    let cancelled = false
    setState({ loading: true })
    api
      .post(`/captures/${captureId}/rpc`, { method: 'follow', params: { follow: target.kind, filter: target.filter } })
      .then((answer) => !cancelled && setState({ loading: false, data: answer.result }))
      .catch((err) => !cancelled && setState({ loading: false, error: err.message }))
    return () => {
      cancelled = true
    }
  }, [captureId, target])

  const payloads = useMemo(() => state.data?.payloads ?? [], [state.data])
  if (!target) return null
  const data = state.data
  return (
    <Modal open onClose={onClose} title={`Follow ${target.kind} stream (${target.filter})`} maxWidth="max-w-5xl">
      {state.loading && <p className="font-mono text-sm text-fg-muted">Reassembling the stream…</p>}
      {state.error && (
        <p role="alert" className="font-mono text-sm text-high">
          {state.error}
        </p>
      )}
      {data && (
        <div className="space-y-2 font-mono text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2 text-fg-muted">
            <span>
              <span className="text-high">
                {data.chost}:{data.cport}
              </span>{' '}
              → {data.shost}:{data.sport} · <span className="text-high">client {data.cbytes} bytes</span> ·{' '}
              <span className="text-info">server {data.sbytes} bytes</span>
            </span>
            <span className="flex gap-1" role="tablist" aria-label="Show as">
              {MODES.map((m) => (
                <button
                  key={m.id}
                  type="button"
                  role="tab"
                  aria-selected={mode === m.id}
                  onClick={() => setMode(m.id)}
                  className={[
                    'border px-2 py-0.5',
                    mode === m.id ? 'border-accent-strong bg-accent-soft text-accent-fg' : 'border-line',
                  ].join(' ')}
                >
                  {m.label}
                </button>
              ))}
            </span>
          </div>
          <pre
            aria-label="Stream content"
            className="max-h-[65vh] overflow-auto whitespace-pre-wrap break-all border border-line bg-canvas p-2 text-[11px] leading-4"
          >
            {payloads.map((p, i) => (
              <span key={i} className={p.s ? 'text-info' : 'text-high'}>
                {mode === 'ascii'
                  ? base64Text(p.d)
                  : hexRows(fromBase64(p.d))
                      .map((row) => `${formatOffset(row.offset)}  ${row.hex.join(' ').padEnd(47, ' ')}  ${row.ascii}`)
                      .join('\n') + '\n'}
              </span>
            ))}
          </pre>
        </div>
      )}
    </Modal>
  )
}
