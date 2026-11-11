import { useRef, useState } from 'react'
import { Upload } from 'lucide-react'
import { Button, Modal } from '../ui/index.js'

/*
 * "New analysis": the entry point for analysing something without opening an
 * incident first. One area takes a file (dropped or chosen); Nik then
 * recognises what it is and asks where it goes, exactly as for a file dropped
 * anywhere in the app (AddFileDialog), with "Start analysis" preselected.
 */

/**
 * @param {{ open: boolean, onClose: () => void, onFile: (file: File) => void }} props
 */
export default function NewAnalysisDialog({ open, onClose, onFile }) {
  const input = useRef(null)
  const [over, setOver] = useState(false)

  const take = (file) => {
    if (file) onFile(file)
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
      <div className="space-y-3">
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
            'flex w-full flex-col items-center gap-2 border border-dashed px-4 py-10 text-center transition-colors',
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
        <p className="text-xs text-fg-muted">
          Nothing is executed: files are stored read-only on the Nik server and analysed statically. You choose next
          whether it stays on its own or goes into an incident.
        </p>
      </div>
    </Modal>
  )
}
