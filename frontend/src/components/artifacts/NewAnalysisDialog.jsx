import { useEffect, useRef, useState } from 'react'
import { Search, Upload } from 'lucide-react'
import { Button, Modal } from '../ui/index.js'
import { urlFromText } from '../../domain/urlscan.js'

/*
 * "New analysis": the entry point for analysing something without opening an
 * incident first. One dialog takes either:
 *
 *  - a file (dropped or chosen): Nik then recognises what it is and asks where
 *    it goes, exactly as for a file dropped anywhere in the app
 *    (AddFileDialog), with "Start analysis" preselected;
 *  - an address (typed or pasted, defanged text included): the isolated
 *    browser visits it and the scan opens as an artifact.
 */

/**
 * @param {{
 *   open: boolean,
 *   onClose: () => void,
 *   onFile: (file: File) => void,
 *   onUrl: (url: string) => Promise<void>,   // rejects with the reason an address is refused
 *   initialUrl?: string,                      // prefilled (an address pasted or dropped on the app)
 * }} props
 */
export default function NewAnalysisDialog({ open, onClose, onFile, onUrl, initialUrl = '' }) {
  const input = useRef(null)
  const [over, setOver] = useState(false)
  const [address, setAddress] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    setAddress(initialUrl)
    setError(null)
    setBusy(false)
  }, [open, initialUrl])

  const take = (file) => {
    if (file) onFile(file)
  }

  const submit = async (event) => {
    event.preventDefault()
    const url = urlFromText(address)
    if (!url) {
      setError('Type an http or https address.')
      return
    }
    setBusy(true)
    setError(null)
    try {
      await onUrl(url)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="New analysis"
      maxWidth="max-w-xl"
      footer={
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
      }
    >
      <div className="space-y-4">
        <button
          type="button"
          aria-label="Choose a file to analyse"
          onClick={() => input.current?.click()}
          onDragOver={(event) => {
            event.preventDefault()
            setOver(true)
          }}
          onDragLeave={() => setOver(false)}
          onDrop={(event) => {
            // Handled here: the app-wide drop handler ignores a prevented drop.
            event.preventDefault()
            setOver(false)
            take(event.dataTransfer.files?.[0])
          }}
          className={[
            'flex w-full flex-col items-center gap-2 border border-dashed px-4 py-8 text-center transition-colors',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
            over ? 'border-accent bg-accent-soft' : 'border-accent-strong bg-panel hover:bg-raised',
          ].join(' ')}
        >
          <Upload className="h-7 w-7 text-accent" aria-hidden="true" />
          <span className="font-mono text-sm font-semibold text-fg">Drop a file, or click to choose</span>
          <span className="text-xs text-fg-muted">
            e-mail (.eml, .msg) · suspicious file · packet capture (.pcap, .pcapng)
          </span>
        </button>
        <input
          ref={input}
          type="file"
          hidden
          aria-label="File to analyse"
          onChange={(event) => {
            take(event.target.files?.[0])
            event.target.value = ''
          }}
        />

        <form onSubmit={submit} className="space-y-2">
          <label htmlFor="new-analysis-url" className="block font-mono text-xs text-fg-muted">
            or an address to scan
          </label>
          <div className="flex gap-2">
            <input
              id="new-analysis-url"
              value={address}
              onChange={(event) => setAddress(event.target.value)}
              placeholder="https://… (hxxps://evil[.]top works too)"
              className="h-9 min-w-0 flex-1 border border-line bg-canvas px-3 font-mono text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            />
            <Button type="submit" icon={Search} disabled={busy || !address.trim()}>
              {busy ? 'Starting…' : 'Scan address'}
            </Button>
          </div>
          {error && (
            <p role="alert" className="font-mono text-xs text-high">
              {error}
            </p>
          )}
        </form>

        <p className="text-xs text-fg-muted">
          Nothing is executed: files are stored read-only on the Nik server and analysed statically; an address is
          visited by the isolated browser, which types and submits nothing. You can link the result to an incident
          afterwards.
        </p>
      </div>
    </Modal>
  )
}
