import { useEffect, useMemo, useRef, useState } from 'react'
import { Download, Eye, FileText, Loader2 } from 'lucide-react'
import { Button, Modal } from '../ui/index.js'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useSocEngine } from '../../context/SettingsContext.jsx'
import { postForBlob } from '../../services/api.js'
import {
  LANGUAGE_OPTIONS,
  REPORT_SECTIONS,
  TLP_OPTIONS,
  reportDetections,
  reportSettings,
} from '../../domain/report.js'
import { buildTimelineEvents } from '../../domain/timeline.js'

/*
 * Incident report dialog: language, TLP, sections and the executive summary
 * (saved on the incident), a preview of the server-built HTML in a sandboxed
 * frame, and the PDF or HTML download. The app sends the SOC rule hits it
 * computed, so the report can list their ATT&CK techniques.
 */

const inputBase =
  'border border-line bg-canvas px-2.5 py-1.5 text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

function saveBlob(blob, fileName) {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = fileName
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

const safeName = (name) => String(name || 'incident').replace(/[^A-Za-z0-9._-]+/g, '_')

export default function ReportDialog({ open, onClose, incident }) {
  const { updateReportSettings } = useIncidents()
  const engine = useSocEngine()
  const [options, setOptions] = useState(() => reportSettings(incident))
  const [busy, setBusy] = useState(null) // 'preview' | 'pdf' | 'html'
  const [error, setError] = useState(null)
  const [preview, setPreview] = useState(null)
  const summaryTimer = useRef(null)

  useEffect(() => {
    if (!open) return
    setOptions(reportSettings(incident))
    setPreview(null)
    setError(null)
    // Reopening for another incident resets the form; edits re-render only.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, incident?.id])

  const detections = useMemo(
    () =>
      open && incident
        ? reportDetections(
            buildTimelineEvents(incident.data, engine),
            // A report of what was flagged counts the detections on flagged events only.
            options.scope === 'all' ? null : (incident.flags ?? {}),
          )
        : [],
    [open, incident, engine, options.scope],
  )

  if (!incident) return null
  const flaggedCount = Object.keys(incident.flags ?? {}).length

  const update = (patch, { debounce = false } = {}) => {
    setOptions((prev) => ({ ...prev, ...patch }))
    clearTimeout(summaryTimer.current)
    if (debounce) summaryTimer.current = setTimeout(() => updateReportSettings(incident.id, patch), 600)
    else updateReportSettings(incident.id, patch)
  }

  const toggleSection = (id) =>
    update({
      sections: options.sections.includes(id)
        ? options.sections.filter((s) => s !== id)
        : REPORT_SECTIONS.map((s) => s.id).filter((s) => s === id || options.sections.includes(s)),
    })

  const generate = async (format) => {
    setBusy(format === 'html' && !preview ? 'preview' : format)
    setError(null)
    try {
      const blob = await postForBlob(`/incidents/${encodeURIComponent(incident.id)}/report`, {
        format,
        ...options,
        detections,
      })
      return blob
    } catch (err) {
      setError(err?.message ?? 'The report could not be generated.')
      return null
    } finally {
      setBusy(null)
    }
  }

  const handlePreview = async () => {
    const blob = await generate('html')
    if (blob) setPreview(await blob.text())
  }
  const handleDownload = async (format) => {
    const blob = await generate(format)
    if (blob) saveBlob(blob, `${safeName(incident.name)}-report.${format}`)
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Incident report"
      maxWidth="max-w-5xl"
      footer={
        <>
          {error && <span className="mr-auto text-xs text-high">{error}</span>}
          <Button variant="secondary" icon={Eye} onClick={handlePreview} disabled={Boolean(busy)}>
            {busy === 'preview' ? 'Building…' : 'Preview'}
          </Button>
          <Button variant="secondary" icon={Download} onClick={() => handleDownload('html')} disabled={Boolean(busy)}>
            HTML
          </Button>
          <Button
            icon={busy === 'pdf' ? Loader2 : Download}
            onClick={() => handleDownload('pdf')}
            disabled={Boolean(busy)}
          >
            {busy === 'pdf' ? 'Rendering…' : 'Download PDF'}
          </Button>
        </>
      }
    >
      <div className="grid gap-5 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]">
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <label className="space-y-1 text-xs text-fg-muted">
              <span className="block font-mono">Language</span>
              <select
                value={options.lang}
                onChange={(e) => update({ lang: e.target.value })}
                className={`${inputBase} w-full`}
              >
                {LANGUAGE_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="space-y-1 text-xs text-fg-muted">
              <span className="block font-mono">Classification</span>
              <select
                value={options.tlp}
                onChange={(e) => update({ tlp: e.target.value })}
                className={`${inputBase} w-full`}
              >
                {TLP_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <fieldset className="space-y-1.5">
            <legend className="mb-1 font-mono text-xs text-fg-muted">Content</legend>
            <label className="flex items-start gap-2 text-sm text-fg">
              <input
                type="checkbox"
                checked={options.scope === 'all'}
                onChange={(event) => update({ scope: event.target.checked ? 'all' : 'flagged' })}
                className="mt-0.5 accent-accent"
              />
              <span>
                Include everything
                <span className="block text-xs text-fg-muted">
                  {options.scope === 'all'
                    ? 'Every indicator, sample, e-mail, capture and imported file of the incident.'
                    : `Only what is flagged (${flaggedCount} item${flaggedCount === 1 ? '' : 's'}): flag from the right-click menu.`}
                </span>
              </span>
            </label>
          </fieldset>

          <fieldset className="space-y-1.5">
            <legend className="mb-1 font-mono text-xs text-fg-muted">Sections</legend>
            {REPORT_SECTIONS.map((section) => (
              <label key={section.id} className="flex items-center gap-2 text-sm text-fg">
                <input
                  type="checkbox"
                  checked={options.sections.includes(section.id)}
                  onChange={() => toggleSection(section.id)}
                  className="accent-accent"
                />
                {section.label}
              </label>
            ))}
          </fieldset>

          <label className="block space-y-1">
            <span className="block font-mono text-xs text-fg-muted">Executive summary</span>
            <textarea
              value={options.executiveSummary}
              onChange={(e) => update({ executiveSummary: e.target.value }, { debounce: true })}
              rows={8}
              maxLength={20000}
              placeholder="What happened, the impact, what was done and what should happen next. Saved with the incident."
              className={`${inputBase} w-full font-sans`}
            />
          </label>
          <p className="text-[11px] text-fg-muted">
            {detections.length} SOC rules matched in this incident; their ATT&amp;CK techniques join those from capa and
            YARA. The organisation name and logo come from Settings → Report header.
          </p>
        </div>

        <div className="flex min-h-[28rem] flex-col border border-line bg-canvas">
          {preview ? (
            <iframe title="Report preview" sandbox="" srcDoc={preview} className="h-[60vh] w-full flex-1 bg-white" />
          ) : (
            <div className="flex flex-1 flex-col items-center justify-center gap-2 p-6 text-center text-sm text-fg-muted">
              {busy === 'preview' ? (
                <Loader2 className="h-6 w-6 animate-spin" />
              ) : (
                <FileText className="h-8 w-8 text-fg-subtle" />
              )}
              <p>Preview the report as the server builds it, then download it as PDF or HTML.</p>
            </div>
          )}
        </div>
      </div>
    </Modal>
  )
}
