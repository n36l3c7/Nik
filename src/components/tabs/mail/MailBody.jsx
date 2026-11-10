import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, ImageOff, Image as ImageIcon } from 'lucide-react'
import { Badge, Button, Modal } from '../../ui/index.js'
import { api } from '../../../services/api.js'
import { frameDocument, neutraliseLinks } from '../../../utils/mail.js'

/*
 * The message body three ways:
 *   Text    the plain-text part (or the HTML reduced to text);
 *   HTML    the HTML as the recipient saw it, rendered in a sandboxed frame:
 *           sanitised on the server (no scripts, handlers, forms, frames),
 *           links disarmed (their target in a tooltip), and a
 *           Content-Security-Policy that blocks every request. Remote images
 *           load only when the analyst asks, after a warning; tracking pixels
 *           never do;
 *   Source  the raw HTML part, or the whole .eml as received.
 * Hidden text (zero-size, white on white…) is revealed and outlined in red.
 */

const MODES = [
  { id: 'html', label: 'HTML' },
  { id: 'text', label: 'Text' },
  { id: 'source', label: 'Source' },
]

export default function MailBody({ message, analysis }) {
  const body = analysis.body
  const [mode, setMode] = useState(body.hasHtml ? 'html' : 'text')
  const [loadImages, setLoadImages] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [source, setSource] = useState(null)
  const [sourceKind, setSourceKind] = useState('html')
  const tracking = useMemo(() => body.remoteImages.filter((i) => i.tracking).map((i) => i.url), [body.remoteImages])
  const remote = body.remoteImages.length
  const realImages = remote - tracking.length

  useEffect(() => {
    setLoadImages(false)
    setSource(null)
  }, [message.sha256])

  useEffect(() => {
    if (mode !== 'source' || sourceKind !== 'raw' || source) return
    let cancelled = false
    api
      .get(`/mails/${message.sha256}/source`)
      .then((res) => !cancelled && setSource(res))
      .catch((err) => !cancelled && setSource({ available: false, error: err.message }))
    return () => {
      cancelled = true
    }
  }, [mode, sourceKind, source, message.sha256])

  const srcDoc = useMemo(
    () => (body.html ? frameDocument(neutraliseLinks(body.html, { loadImages, tracking }), { loadImages }) : ''),
    [body.html, loadImages, tracking],
  )

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div role="tablist" aria-label="Body views" className="flex gap-1">
          {MODES.filter((m) => m.id !== 'html' || body.hasHtml).map((m) => (
            <button
              key={m.id}
              type="button"
              role="tab"
              aria-selected={mode === m.id}
              onClick={() => setMode(m.id)}
              className={[
                'border px-2.5 py-1 font-mono text-xs transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                mode === m.id
                  ? 'border-accent-strong bg-accent-soft text-accent-fg'
                  : 'border-line text-fg-muted hover:text-fg',
              ].join(' ')}
            >
              {m.label}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          {body.hiddenElements > 0 && (
            <Badge color="red" title="Text the recipient could not see, shown here outlined in red">
              {body.hiddenElements} hidden
            </Badge>
          )}
          {tracking.length > 0 && (
            <Badge color="amber" title="Images that tell the sender the message was opened: never loaded">
              {tracking.length} tracking pixel{tracking.length > 1 ? 's' : ''}
            </Badge>
          )}
          {mode === 'html' && realImages > 0 && (
            <Button
              variant={loadImages ? 'ghost' : 'secondary'}
              size="xs"
              icon={loadImages ? ImageOff : ImageIcon}
              onClick={() => (loadImages ? setLoadImages(false) : setConfirming(true))}
            >
              {loadImages ? 'Block images' : `Load ${realImages} image${realImages > 1 ? 's' : ''}`}
            </Button>
          )}
        </div>
      </div>

      {mode === 'html' && (
        <iframe
          title="Message body (sandboxed)"
          sandbox=""
          referrerPolicy="no-referrer"
          srcDoc={srcDoc}
          className="h-[60vh] w-full border border-line bg-white"
        />
      )}
      {mode === 'text' && (
        <pre className="max-h-[60vh] overflow-auto whitespace-pre-wrap break-words border border-line bg-canvas p-3 font-mono text-xs text-fg">
          {body.text || '(no text)'}
        </pre>
      )}
      {mode === 'source' && (
        <div className="space-y-2">
          <div className="flex gap-3 font-mono text-xs">
            {body.hasHtml && (
              <label className="flex items-center gap-1.5 text-fg-muted">
                <input
                  type="radio"
                  name="mail-source"
                  className="accent-accent"
                  checked={sourceKind === 'html'}
                  onChange={() => setSourceKind('html')}
                />
                HTML part
              </label>
            )}
            <label className="flex items-center gap-1.5 text-fg-muted">
              <input
                type="radio"
                name="mail-source"
                className="accent-accent"
                checked={sourceKind === 'raw' || !body.hasHtml}
                onChange={() => setSourceKind('raw')}
              />
              Whole message
            </label>
          </div>
          <pre className="max-h-[60vh] overflow-auto whitespace-pre-wrap break-all border border-line bg-canvas p-3 font-mono text-[11px] text-fg">
            {sourceKind === 'html' && body.hasHtml
              ? body.htmlSource
              : source === null
                ? 'Loading…'
                : source.available
                  ? source.text + (source.truncated ? '\n… (truncated)' : '')
                  : (source.error ?? 'An Outlook .msg keeps no original text: see the Headers view.')}
          </pre>
        </div>
      )}

      <Modal
        open={confirming}
        onClose={() => setConfirming(false)}
        title="Load remote images?"
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirming(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                setLoadImages(true)
                setConfirming(false)
              }}
            >
              Load images
            </Button>
          </>
        }
      >
        <div className="space-y-3 font-mono text-sm">
          <p className="flex gap-2 border-l-2 border-med-line bg-med-soft px-3 py-2 text-xs text-med-fg">
            <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden="true" />
            Your browser will fetch {realImages} image{realImages > 1 ? 's' : ''} from the sender&apos;s servers. They
            see your IP address and that the message was opened, and may tailor what they serve.
          </p>
          <p className="text-xs text-fg-muted">
            The {tracking.length} tracking pixel{tracking.length === 1 ? '' : 's'} stay blocked, scripts and links stay
            disabled. Prefer an isolated analysis machine for messages you have not triaged.
          </p>
        </div>
      </Modal>
    </div>
  )
}
