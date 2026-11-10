import { useEffect, useRef, useState } from 'react'
import { FileText, ImagePlus, Save, Trash2 } from 'lucide-react'
import { Button } from '../../ui/index.js'
import { useSettings } from '../../../context/SettingsContext.jsx'

/*
 * Report header: the organisation name and logo printed at the top of every
 * incident report (HTML and PDF). Shared by every analyst. The logo is kept
 * in the settings as a data: URI (PNG, JPEG or SVG, up to 256 KB).
 */

const MAX_LOGO_BYTES = 256 * 1024
const LOGO_TYPES = ['image/png', 'image/jpeg', 'image/svg+xml']

const readAsDataUrl = (file) =>
  new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result))
    reader.onerror = () => reject(reader.error)
    reader.readAsDataURL(file)
  })

export default function ReportBrandingSection() {
  const { reportBranding, setReportBranding } = useSettings()
  const inputRef = useRef(null)
  const [orgName, setOrgName] = useState(reportBranding?.orgName ?? '')
  const [error, setError] = useState(null)
  const loaded = reportBranding != null

  useEffect(() => {
    setOrgName(reportBranding?.orgName ?? '')
  }, [reportBranding?.orgName])

  const handleLogo = async (file) => {
    setError(null)
    if (!file) return
    if (!LOGO_TYPES.includes(file.type)) return setError('Use a PNG, JPEG or SVG image.')
    if (file.size > MAX_LOGO_BYTES) return setError('The logo must be 256 KB or smaller.')
    setReportBranding({ logo: await readAsDataUrl(file) })
  }

  return (
    <section className="space-y-4">
      <div>
        <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
          <FileText className="h-4 w-4 text-accent" />
          Report header
        </h3>
        <p className="mt-1 text-xs text-fg-muted">
          The organisation name and logo printed on every incident report (HTML and PDF), for every analyst.
        </p>
      </div>

      <div className="space-y-1.5">
        <label htmlFor="report-org" className="block font-mono text-xs text-fg-muted">
          Organisation
        </label>
        <div className="flex gap-2">
          <input
            id="report-org"
            type="text"
            value={orgName}
            maxLength={200}
            disabled={!loaded}
            onChange={(e) => setOrgName(e.target.value)}
            placeholder="e.g. ACME Security Operations Center"
            className="min-w-0 flex-1 border border-line bg-canvas px-3 py-1.5 text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          />
          <Button
            icon={Save}
            size="sm"
            disabled={!loaded || orgName.trim() === (reportBranding?.orgName ?? '')}
            onClick={() => setReportBranding({ orgName: orgName.trim() })}
          >
            Save
          </Button>
        </div>
      </div>

      <div className="space-y-1.5">
        <span className="block font-mono text-xs text-fg-muted">Logo</span>
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex h-16 w-40 items-center justify-center border border-dashed border-line bg-white p-2">
            {reportBranding?.logo ? (
              <img src={reportBranding.logo} alt="Report logo" className="max-h-full max-w-full" />
            ) : (
              <span className="text-[11px] text-fg-subtle">no logo</span>
            )}
          </div>
          <input
            ref={inputRef}
            type="file"
            accept={LOGO_TYPES.join(',')}
            hidden
            onChange={(e) => {
              handleLogo(e.target.files?.[0])
              e.target.value = ''
            }}
          />
          <Button
            variant="secondary"
            size="sm"
            icon={ImagePlus}
            disabled={!loaded}
            onClick={() => inputRef.current?.click()}
          >
            Choose an image
          </Button>
          {reportBranding?.logo && (
            <Button variant="ghost" size="sm" icon={Trash2} onClick={() => setReportBranding({ logo: '' })}>
              Remove
            </Button>
          )}
        </div>
        <p className="text-[11px] text-fg-muted">PNG, JPEG or SVG, up to 256 KB. Shown on a white page.</p>
        {error && <p className="text-xs text-high">{error}</p>}
      </div>
    </section>
  )
}
