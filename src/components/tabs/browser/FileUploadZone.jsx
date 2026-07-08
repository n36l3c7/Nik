import { useRef, useState } from 'react'
import {
  AlertTriangle,
  Database,
  FileJson,
  FileSpreadsheet,
  Sparkles,
  Upload,
  X,
} from 'lucide-react'
import Badge from '../../ui/Badge.jsx'
import Spinner from '../../ui/Spinner.jsx'
import { formatDateTime } from '../../../utils/time.js'

/*
 * Drag & drop upload zone for a single browser artifact
 * (History / Bookmarks / Shortcuts). Three visual states with a consistent
 * height: empty (drop invitation), loading (spinner) and "imported" (file
 * metadata). Any parsing error is shown below the zone.
 */

/** Icon representing the format of the imported file. */
const FORMAT_ICONS = {
  sqlite: Database,
  json: FileJson,
  csv: FileSpreadsheet,
  demo: Sparkles,
}

/** Badge color depending on the format. */
const FORMAT_COLORS = {
  sqlite: 'cyan',
  json: 'emerald',
  csv: 'amber',
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
          'rounded-xl border-2 border-dashed p-4 text-center transition-colors',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500',
          isDragging
            ? 'border-cyan-500 bg-cyan-500/5 dark:border-cyan-400 dark:bg-cyan-400/10'
            : 'border-slate-300 bg-slate-50 hover:border-cyan-500/60 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-900/60 dark:hover:border-cyan-400/60 dark:hover:bg-slate-800/60',
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
          <div className="flex flex-col items-center gap-2">
            <Spinner className="h-6 w-6 text-cyan-600 dark:text-cyan-400" />
            <p className="text-sm text-slate-500 dark:text-slate-400">Analyzing…</p>
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
              className="absolute right-2 top-2 rounded-md p-1 text-slate-400 transition-colors hover:bg-red-500/10 hover:text-red-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 dark:text-slate-500 dark:hover:text-red-400"
            >
              <X className="h-4 w-4" />
            </button>

            <FormatIcon className="h-7 w-7 text-cyan-600 dark:text-cyan-400" />
            <p
              className="max-w-full truncate text-sm font-medium text-slate-800 dark:text-slate-200"
              title={meta.fileName}
            >
              {meta.fileName}
            </p>
            <div className="flex flex-wrap items-center justify-center gap-2">
              <Badge color={FORMAT_COLORS[meta.format] ?? 'slate'}>
                {String(meta.format).toUpperCase()}
              </Badge>
              <span className="text-xs text-slate-500 dark:text-slate-400">
                {Number(meta.rows ?? 0).toLocaleString('en-US')} rows
              </span>
            </div>
            <p className="font-mono text-xs text-slate-500 dark:text-slate-400">
              {formatDateTime(Date.parse(meta.importedAt))}
            </p>
          </div>
        ) : (
          /* ---- State: empty, drop invitation ---- */
          <div className="flex flex-col items-center gap-2">
            <span className="rounded-lg bg-cyan-600/10 p-2 text-cyan-600 dark:bg-cyan-400/10 dark:text-cyan-400">
              {Icon ? <Icon className="h-6 w-6" /> : <Upload className="h-6 w-6" />}
            </span>
            <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">{label}</p>
            <p className="text-xs text-slate-500 dark:text-slate-400">{description}</p>
            <p className="text-xs text-slate-400 dark:text-slate-500">
              Drag a file here or click to select
            </p>
            {pathHint && (
              // Typical path of the file on disk (disappears once loaded)
              <p
                className="mt-1 break-all rounded bg-slate-100 px-2 py-1 font-mono text-[10px] text-slate-500 dark:bg-slate-800 dark:text-slate-400"
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
          className="flex items-start gap-1.5 text-xs text-red-600 dark:text-red-400"
        >
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{error}</span>
        </p>
      )}
    </div>
  )
}
