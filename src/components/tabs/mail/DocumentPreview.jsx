import { useEffect, useState } from 'react'
import { ChevronLeft, ChevronRight, ZoomIn, ZoomOut } from 'lucide-react'
import { AsciiSkull, Button, Modal } from '../../ui/index.js'
import { api } from '../../../services/api.js'

/*
 * A document attachment as page images (PDF, Office, OpenDocument, RTF,
 * images). The document viewer worker renders them in its own container,
 * LibreOffice with macros disabled, then pdfium: the browser only receives
 * PNG images, nothing in the document runs here.
 */

export default function DocumentPreview({ target, onClose }) {
  const [state, setState] = useState({ loading: true })
  const [page, setPage] = useState(0)
  const [zoom, setZoom] = useState(1)

  useEffect(() => {
    if (!target) return undefined
    let cancelled = false
    setState({ loading: true })
    setPage(0)
    setZoom(1)
    api
      .post(`/mails/${target.sha256}/attachments/${target.path}/preview`)
      .then((res) => !cancelled && setState({ loading: false, data: res }))
      .catch((err) => !cancelled && setState({ loading: false, error: err.message }))
    return () => {
      cancelled = true
    }
  }, [target])

  if (!target) return null
  const pages = state.data?.pages ?? []
  const current = pages[page]

  return (
    <Modal open onClose={onClose} title={`Preview · ${target.name}`} maxWidth="max-w-5xl">
      {state.loading ? (
        <div aria-busy="true" className="flex flex-col items-center gap-3 py-10 font-mono">
          <AsciiSkull preset="medium" />
          <p role="status" className="text-sm text-fg-muted">
            Rendering the document in the isolated viewer…
          </p>
        </div>
      ) : state.error ? (
        <p role="alert" className="py-6 text-center font-mono text-sm text-high">
          {state.error}
        </p>
      ) : (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-xs text-fg-muted">
            <span>
              Page {page + 1} of {pages.length}
              {state.data.total > pages.length && ` (first ${pages.length} of ${state.data.total} shown)`}
              {state.data.converted && ' · converted by LibreOffice, macros disabled'}
            </span>
            <span className="flex items-center gap-1">
              <Button
                variant="ghost"
                size="xs"
                icon={ZoomOut}
                aria-label="Zoom out"
                onClick={() => setZoom((z) => Math.max(0.5, z - 0.25))}
              />
              <span className="w-10 text-center tabular-nums">{Math.round(zoom * 100)} %</span>
              <Button
                variant="ghost"
                size="xs"
                icon={ZoomIn}
                aria-label="Zoom in"
                onClick={() => setZoom((z) => Math.min(3, z + 0.25))}
              />
              <Button
                variant="ghost"
                size="xs"
                icon={ChevronLeft}
                aria-label="Previous page"
                disabled={page === 0}
                onClick={() => setPage((p) => p - 1)}
              />
              <Button
                variant="ghost"
                size="xs"
                icon={ChevronRight}
                aria-label="Next page"
                disabled={page >= pages.length - 1}
                onClick={() => setPage((p) => p + 1)}
              />
            </span>
          </div>
          <div className="max-h-[70vh] overflow-auto border border-line bg-canvas p-2">
            {current && (
              <img
                src={`data:image/png;base64,${current.png}`}
                alt={`Page ${page + 1} of ${target.name}`}
                style={{ width: `${zoom * 100}%`, maxWidth: 'none' }}
                className="mx-auto block bg-white"
              />
            )}
          </div>
          {pages.length > 1 && (
            <div className="flex gap-2 overflow-x-auto pb-1" aria-label="Pages">
              {pages.map((p, i) => (
                <button
                  key={i}
                  type="button"
                  onClick={() => setPage(i)}
                  aria-label={`Page ${i + 1}`}
                  aria-current={i === page ? 'true' : undefined}
                  className={[
                    'shrink-0 border bg-white',
                    i === page ? 'border-accent-strong ring-2 ring-accent' : 'border-line',
                  ].join(' ')}
                >
                  <img src={`data:image/png;base64,${p.png}`} alt="" className="h-20 w-auto" />
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </Modal>
  )
}
