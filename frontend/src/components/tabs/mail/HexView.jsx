import { useEffect, useState } from 'react'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from '../../ui/index.js'
import { api } from '../../../services/api.js'
import { formatOffset, hexRows } from '../../../domain/mail.js'

/*
 * An attachment's bytes, 4 KiB at a time: offset, hex and ASCII columns. The
 * bytes come from the server as base64 and are only drawn, never opened.
 */

const PAGE = 4096

export default function HexView({ sha256, path }) {
  const [offset, setOffset] = useState(0)
  const [state, setState] = useState({ loading: true })

  useEffect(() => setOffset(0), [sha256, path])

  useEffect(() => {
    let cancelled = false
    setState((prev) => ({ ...prev, loading: true }))
    api
      .get(`/mails/${sha256}/attachments/${path}/bytes?offset=${offset}&length=${PAGE}`)
      .then((res) => {
        if (cancelled) return
        const raw = atob(res.data)
        const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0))
        setState({ loading: false, size: res.size, rows: hexRows(bytes, offset) })
      })
      .catch((err) => !cancelled && setState({ loading: false, error: err.message }))
    return () => {
      cancelled = true
    }
  }, [sha256, path, offset])

  if (state.error)
    return (
      <p role="alert" className="font-mono text-xs text-high">
        {state.error}
      </p>
    )
  const size = state.size ?? 0
  return (
    <div className="space-y-2" aria-busy={state.loading}>
      <div className="flex items-center justify-between font-mono text-[11px] text-fg-muted">
        <span>
          {size
            ? `${formatOffset(offset)}–${formatOffset(Math.min(size, offset + PAGE) - 1)} of ${size.toLocaleString('en-US')} bytes`
            : '…'}
        </span>
        <span className="flex gap-1">
          <Button
            variant="ghost"
            size="xs"
            icon={ChevronLeft}
            aria-label="Previous 4 KiB"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE))}
          />
          <Button
            variant="ghost"
            size="xs"
            icon={ChevronRight}
            aria-label="Next 4 KiB"
            disabled={offset + PAGE >= size}
            onClick={() => setOffset(offset + PAGE)}
          />
        </span>
      </div>
      <pre className="max-h-80 overflow-auto border border-line bg-canvas p-2 font-mono text-[11px] leading-4 text-fg">
        {(state.rows ?? []).map((row) => (
          <div key={row.offset} className="whitespace-pre">
            <span className="text-fg-subtle">{formatOffset(row.offset)}</span>
            {'  '}
            {row.hex.join(' ').padEnd(47, ' ')}
            {'  '}
            <span className="text-accent-fg">{row.ascii}</span>
          </div>
        ))}
      </pre>
    </div>
  )
}
