import { useEffect, useMemo, useState } from 'react'
import { Download } from 'lucide-react'
import { postForBlob } from '../../services/api.js'
import { copyText, saveBlob } from '../../lib/download.js'
import { EXPORT_FIELDS, EXPORT_FORMATS, cleanExportFields } from '../../domain/iocLibrary.js'
import { useToast } from '../../context/ToastContext.jsx'
import { Button, Modal } from '../ui/index.js'

/*
 * Export a list, a selection or a filter: the format, the fields (only the
 * main ones are ticked at first; the choice is remembered in this browser)
 * and a preview of the first rows as the server writes them.
 */

const STORE = 'nik.iocExport'
const EXTENSIONS = { csv: 'csv', json: 'json', stix: 'stix.json', misp: 'misp.json', txt: 'txt' }

function stored() {
  try {
    return JSON.parse(localStorage.getItem(STORE) ?? '{}') ?? {}
  } catch {
    return {}
  }
}

/**
 * @param {{ request: { scope: object, label: string, count?: number } | null, onClose: () => void }} props
 */
export default function ExportIocsDialog({ request, onClose }) {
  const { showToast } = useToast()
  const [format, setFormat] = useState('csv')
  const [fields, setFields] = useState(() => cleanExportFields(null))
  const [defang, setDefang] = useState(false)
  const [flaggedOnly, setFlaggedOnly] = useState(false)
  const [allowlisted, setAllowlisted] = useState(false)
  const [expired, setExpired] = useState(false)
  const [preview, setPreview] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!request) return
    const saved = stored()
    setFormat(EXPORT_FORMATS.some((f) => f.id === saved.format) ? saved.format : 'csv')
    setFields(cleanExportFields(saved.fields))
    setDefang(Boolean(saved.defang))
    setFlaggedOnly(false)
    setAllowlisted(false)
    setExpired(false)
    setError(null)
  }, [request])

  const body = useMemo(
    () => (request ? { scope: request.scope, format, fields, defang, flaggedOnly, allowlisted, expired } : null),
    [request, format, fields, defang, flaggedOnly, allowlisted, expired],
  )

  useEffect(() => {
    if (!body) return undefined
    let cancelled = false
    const timer = setTimeout(() => {
      postForBlob('/iocs/export', { ...body, preview: true })
        .then((blob) => blob.text())
        .then((text) => !cancelled && (setPreview(text.split('\n').slice(0, 14).join('\n')), setError(null)))
        .catch((err) => !cancelled && setError(err.message))
    }, 200)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [body])

  if (!request) return null
  const withFields = EXPORT_FORMATS.find((f) => f.id === format)?.fields
  const remember = () => {
    try {
      localStorage.setItem(STORE, JSON.stringify({ format, fields, defang }))
    } catch {
      /* private window: the choice is not kept */
    }
  }
  const toggle = (id) =>
    setFields((current) => {
      const next = current.includes(id) ? current.filter((f) => f !== id) : [...current, id]
      return EXPORT_FIELDS.map((f) => f.id).filter((f) => next.includes(f))
    })
  const fileName = `${
    request.label
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, '-')
      .replace(/^-|-$/g, '') || 'indicators'
  }.${EXTENSIONS[format]}`
  const run = async (how) => {
    setBusy(true)
    setError(null)
    try {
      const blob = await postForBlob('/iocs/export', body)
      remember()
      if (how === 'copy') {
        showToast({ message: (await copyText(await blob.text())) ? 'Copied.' : 'The browser refused to copy.' })
      } else {
        saveBlob(blob, fileName)
        onClose()
      }
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
      title={`Export · ${request.label}${request.count != null ? ` · ${request.count} indicators` : ''}`}
      maxWidth="max-w-3xl"
      footer={
        <>
          <Button variant="secondary" disabled={busy} onClick={() => run('copy')}>
            Copy
          </Button>
          <Button icon={Download} disabled={busy || (withFields && fields.length === 0)} onClick={() => run('save')}>
            Download {fileName}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <fieldset className="space-y-2">
          <legend className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">Format</legend>
          <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-5">
            {EXPORT_FORMATS.map((option) => (
              <label
                key={option.id}
                className={[
                  'cursor-pointer border px-2.5 py-1.5 font-mono text-xs font-semibold focus-within:ring-2 focus-within:ring-accent',
                  format === option.id ? 'border-accent bg-accent-soft text-accent-fg' : 'border-line text-fg',
                ].join(' ')}
              >
                <input
                  type="radio"
                  name="ioc-export-format"
                  className="sr-only"
                  checked={format === option.id}
                  onChange={() => setFormat(option.id)}
                />
                {option.label}
                <span className="block font-sans text-[11px] font-normal text-fg-subtle">{option.hint}</span>
              </label>
            ))}
          </div>
        </fieldset>

        <fieldset className="space-y-2" disabled={!withFields}>
          <legend className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">
            Fields {!withFields && <span className="normal-case text-fg-subtle">· this format has its own</span>}
          </legend>
          <div className={`grid grid-cols-2 gap-x-4 gap-y-1 sm:grid-cols-3 ${withFields ? '' : 'opacity-50'}`}>
            {EXPORT_FIELDS.map((field) => (
              <label key={field.id} className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={fields.includes(field.id)} onChange={() => toggle(field.id)} />
                {field.label}
              </label>
            ))}
          </div>
        </fieldset>

        <div className="flex flex-wrap gap-x-5 gap-y-1 text-sm">
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={defang} onChange={(event) => setDefang(event.target.checked)} />
            Defang values
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={flaggedOnly} onChange={(event) => setFlaggedOnly(event.target.checked)} />
            Only malicious and suspicious
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={allowlisted} onChange={(event) => setAllowlisted(event.target.checked)} />
            Include allowlisted
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={expired} onChange={(event) => setExpired(event.target.checked)} />
            Include expired
          </label>
        </div>

        <section className="space-y-2">
          <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">Preview (first rows)</h3>
          <pre
            aria-label="Export preview"
            className="max-h-56 overflow-auto border border-line bg-canvas p-2.5 font-mono text-[11px] leading-relaxed text-fg"
          >
            {preview || '(nothing to export with these choices)'}
          </pre>
        </section>
        {error && (
          <p role="alert" className="font-mono text-xs text-high">
            {error}
          </p>
        )}
      </div>
    </Modal>
  )
}
