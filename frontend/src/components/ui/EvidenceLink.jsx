import { useState } from 'react'
import { Copy, ExternalLink, ShieldAlert } from 'lucide-react'
import { evidenceAddress } from '../../domain/links.js'
import Button from './Button.jsx'
import Modal from './Modal.jsx'

/*
 * A link to an address that comes from the evidence (a visited URL, a
 * bookmark, a download source). It is never a real link: one stray click
 * would open a phishing page or an exploit kit from the analyst's own
 * workstation, with their address. The click asks first, shows the address
 * defanged, and only http(s) addresses can be opened at all.
 *
 * `children` is what is shown (an icon, a host name); the rest are the
 * button's attributes.
 */
export default function EvidenceLink({ url, children, className = '', title, 'aria-label': ariaLabel }) {
  const [open, setOpen] = useState(false)
  const [copied, setCopied] = useState(false)
  if (!url) return null
  const address = evidenceAddress(url)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(address.defanged)
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }
  const visit = () => {
    window.open(address.href, '_blank', 'noopener,noreferrer')
    setOpen(false)
  }

  return (
    <>
      <button
        type="button"
        onClick={() => {
          setCopied(false)
          setOpen(true)
        }}
        title={title}
        aria-label={ariaLabel}
        className={className}
      >
        {children}
      </button>
      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Open an address from the evidence?"
        footer={
          <>
            <Button variant="ghost" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button variant="secondary" icon={Copy} onClick={copy}>
              {copied ? 'Copied' : 'Copy defanged'}
            </Button>
            {address.href && (
              <Button variant="danger" icon={ExternalLink} onClick={visit}>
                Open in my browser
              </Button>
            )}
          </>
        }
      >
        <div className="space-y-3">
          <p className="flex items-start gap-2 text-fg-muted">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-med" aria-hidden="true" />
            <span>
              {address.href
                ? 'This address comes from the evidence. Opening it contacts the site from your workstation, with your address. To look at it safely, scan it from URL Analysis instead.'
                : `This address comes from the evidence and is not a web page (${address.scheme || 'no scheme'}): it cannot be opened from here.`}
            </span>
          </p>
          <p className="break-all border border-line bg-canvas px-3 py-2 font-mono text-xs text-fg">
            {address.defanged}
          </p>
        </div>
      </Modal>
    </>
  )
}
