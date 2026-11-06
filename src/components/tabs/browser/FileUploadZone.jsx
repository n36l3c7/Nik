import { useRef, useState } from 'react'
import {
  AlertTriangle,
  Database,
  FileCode,
  FileJson,
  FileSpreadsheet,
  Sparkles,
  Upload,
  X,
} from 'lucide-react'
import Badge from '../../ui/Badge.jsx'
import AsciiSkull from '../../ui/AsciiSkull.jsx'
import { formatDateTime } from '../../../utils/time.js'

/*
 * Drag & drop upload zone for a single browser artifact
 * (History / Bookmarks / Shortcuts / plists). Three visual states with a consistent
 * height: empty (drop invitation), loading (spinner) and "imported" (file
 * metadata). Any parsing error is shown below the zone.
 */

/** Icon representing the format of the imported file. */
const FORMAT_ICONS = {
  sqlite: Database,
  json: FileJson,
  csv: FileSpreadsheet,
  plist: FileCode,
  demo: Sparkles,
}

/** Badge color depending on the format. */
const FORMAT_COLORS = {
  sqlite: 'cyan',
  json: 'emerald',
  csv: 'amber',
  plist: 'violet',
  demo: 'slate',
}

/**
 * @param {{
 *   label: string,
 *   description: string,
 *   icon: import('react').ComponentType,
 *   accept?: string,
 *   meta?: { fileName: string, format: string, rows: number, importedAt: string } | null,
 *   loading?: boolean,
 *   error?: string | null,
 *   pathHint?: string | null,
 *   onFile: (file: File) => void,
 *   onClear: () => void,
 * }} props
 */
export default function FileUploadZone({
  label,
  description,
  icon: Icon,
  accept = '',
  meta = null,
  loading = false,
  error = null,
  pathHint = null,
  onFile,
  onClear,
}) {
  const inputRef = useRef(null)
  // true while a file is being dragged over the zone
  const [isDragging, setIsDragging] = useState(false)

  /** Open the hidden file picker (disabled while loading). */
  const openPicker = () => {
    if (!loading) inputRef.current?.click()
  }

  /** Forward the selected/dropped file to the parent. */
  const handleFile = (file) => {
    if (file) onFile?.(file)
  }

  const handleInputChange = (event) => {
    handleFile(event.target.files?.[0])
    // reset: allows re-loading the same file after an error
    event.target.value = ''
  }

  const handleDragOver = (event) => {
    event.preventDefault()
    if (!loading) setIsDragging(true)
  }

  const handleDragLeave = () => setIsDragging(false)

  const handleDrop = (event) => {
    event.preventDefault()
    setIsDragging(false)
    if (!loading) handleFile(event.dataTransfer?.files?.[0])
  }

  /** Keyboard activation (Enter/Space) for accessibility. */
  const handleKeyDown = (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      openPicker()
    }
  }

  const FormatIcon = FORMAT_ICONS[meta?.format] ?? FileJson

  return (
    <div className="flex flex-col gap-2">
      {/* Interactive area: click or drag & drop */}
      <div
        role="button"
        tabIndex={0}
        aria-label={`Upload ${label} file`}
        onClick={openPicker}
        onKeyDown={handleKeyDown}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={[
          'relative flex min-h-[172px] cursor-pointer flex-col items-center justify-center gap-2',
          'border-2 border-dashed p-4 text-center transition-colors',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
          isDragging
            ? 'border-accent-strong bg-accent-soft'
            : 'border-line bg-canvas hover:border-accent-strong hover:bg-canvas',
        ].join(' ')}
      >
        {/* Hidden file input */}
        <input
          ref={inputRef}
          type="file"
          accept={accept || undefined}
          hidden
          onChange={handleInputChange}
        />

        {loading ? (
          /* ---- State: loading/parsing in progress ---- */
          <div aria-busy="true" className="flex flex-col items-center gap-2">
            <AsciiSkull preset="small" />
            <p role="status" className="font-mono text-sm text-fg-muted">Parsing…</p>
          </div>
        ) : meta ? (
          /* ---- State: file imported, show metadata ---- */
          <div className="flex w-full flex-col items-center gap-2">
            {/* Remove-data button (does not propagate the click to the zone) */}
            <button
              type="button"
              aria-label={`Remove ${label} data`}
              title="Remove imported data"
              onClick={(event) => {
                event.stopPropagation()
                onClear?.()
              }}
              className="absolute right-2 top-2 p-1 text-fg-muted transition-colors hover:bg-high-soft hover:text-high focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <X className="h-4 w-4" />
            </button>

            <FormatIcon className="h-7 w-7 text-accent" />
            <p
              className="max-w-full truncate text-sm font-medium text-fg"
              title={meta.fileName}
            >
              {meta.fileName}
            </p>
            <div className="flex flex-wrap items-center justify-center gap-2">
              <Badge color={FORMAT_COLORS[meta.format] ?? 'slate'}>
                {String(meta.format).toUpperCase()}
              </Badge>
              <span className="text-xs text-fg-muted">
                {Number(meta.rows ?? 0).toLocaleString('en-US')} rows
              </span>
            </div>
            <p className="font-mono text-xs text-fg-muted">
              {formatDateTime(Date.parse(meta.importedAt))}
            </p>
          </div>
        ) : (
          /* ---- State: empty, drop invitation ---- */
          <div className="flex flex-col items-center gap-2">
            <span className="bg-accent-soft p-2 text-accent">
              {Icon ? <Icon className="h-6 w-6" /> : <Upload className="h-6 w-6" />}
            </span>
            <p className="text-sm font-semibold text-fg">{label}</p>
            <p className="text-xs text-fg-muted">{description}</p>
            <p className="text-xs text-fg-muted">
              Drag a file here or click to select
            </p>
            {pathHint && (
              // Typical path of the file on disk (disappears once loaded)
              <p
                className="mt-1 break-all bg-canvas px-2 py-1 font-mono text-[10px] text-fg-muted"
                title={pathHint}
              >
                {pathHint}
              </p>
            )}
          </div>
        )}
      </div>

      {/* Parsing error shown below the zone */}
      {error && (
        <p
          role="alert"
          className="flex items-start gap-1.5 text-xs text-high"
        >
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{error}</span>
        </p>
      )}
    </div>
  )
}
