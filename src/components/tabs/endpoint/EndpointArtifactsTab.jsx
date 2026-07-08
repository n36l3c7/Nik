import { useMemo, useState } from 'react'
import { Info, Sparkles, Terminal, Trash2, Upload } from 'lucide-react'
import { Button, Card, Modal } from '../../ui/index.js'
import FileUploadZone from '../browser/FileUploadZone.jsx'
import ArtifactSection from './ArtifactSection.jsx'
import ScriptBlock from './ScriptBlock.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { parseArtifactImport } from '../../../services/artifactParsers.js'
import { getDemoArtifactData } from '../../../services/demoData.js'
import {
  ARTIFACT_CATEGORIES,
  getArtifactCategoryById,
  buildDefaultArtifactData,
  artifactSourcesFor,
} from '../../../config/artifacts.js'
import { combineCategoryRecords } from '../../../utils/artifacts.js'
import { getOsById, DEFAULT_OS } from '../../../config/os.js'

/*
 * "Endpoint Artifacts" tab: one sub-tab per forensic category. Each category is
 * built from one or more SOURCES, imported per-source in one of two ways
 * (never a third-party tool, see config/artifacts.js):
 *   - mode 'file'   → upload the existing raw file; parsed in-browser.
 *   - mode 'script' → run the shown native script, import the CSV it writes.
 * The table below shows the union of every source's records, tagged by source.
 */

/** Filesystem-safe slug for the downloaded script filename. */
function slugify(text) {
  return String(text).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')
}

/** Total records across a category's sources. */
function totalRecords(catData) {
  return Object.values(catData?.sources ?? {}).reduce(
    (n, s) => n + (s?.records?.length ?? 0),
    0,
  )
}

export default function EndpointArtifactsTab({ incident }) {
  const { updateArtifactSource, clearArtifactSource, clearArtifactCategory } = useIncidents()

  const [activeCategoryId, setActiveCategoryId] = useState(ARTIFACT_CATEGORIES[0].id)
  const [loading, setLoading] = useState({}) // { [sourceKey]: bool }
  const [errors, setErrors] = useState({}) // { [sourceKey]: string }
  const [confirmClear, setConfirmClear] = useState(false)

  const endpointData = incident.data.endpoint
  const os = getOsById(incident.os) ? incident.os : DEFAULT_OS
  const osLabel = getOsById(os)?.label ?? os

  const category = getArtifactCategoryById(activeCategoryId) ?? ARTIFACT_CATEGORIES[0]
  const catData = endpointData.categories[activeCategoryId] ?? buildDefaultArtifactData(category)
  const sources = useMemo(() => artifactSourcesFor(category, os), [category, os])

  const combined = useMemo(
    () => combineCategoryRecords(category, catData),
    [category, catData],
  )
  const hasData = combined.length > 0

  /* ---- Import a file for a specific source ---- */
  const handleFile = async (source, file) => {
    setErrors((p) => ({ ...p, [source.key]: null }))
    setLoading((p) => ({ ...p, [source.key]: true }))
    try {
      const { records, format } = await parseArtifactImport(file, category, source)
      updateArtifactSource(
        incident.id,
        category.id,
        source.key,
        {
          records,
          meta: { fileName: file.name, format, rows: records.length, importedAt: new Date().toISOString() },
        },
        { action: 'endpoint.upload', details: `Imported ${category.label} / ${source.name} (${records.length})` },
      )
    } catch (err) {
      setErrors((p) => ({ ...p, [source.key]: err?.message ?? 'Unexpected error while parsing the file.' }))
    } finally {
      setLoading((p) => ({ ...p, [source.key]: false }))
    }
  }

  /* ---- Load demo data into the first available source ---- */
  const handleLoadDemo = () => {
    if (sources.length === 0) return
    const target = sources[0]
    const demo = getDemoArtifactData(category, os)
    setErrors({})
    updateArtifactSource(
      incident.id,
      category.id,
      target.key,
      {
        records: demo.records,
        meta: { fileName: 'Demo data', format: 'demo', rows: demo.records.length, importedAt: new Date().toISOString() },
      },
      { action: 'endpoint.demo', details: `Loaded demo ${category.label}` },
    )
  }

  const handleConfirmClear = () => {
    clearArtifactCategory(incident.id, category.id)
    setErrors({})
    setConfirmClear(false)
  }

  return (
    <div className="space-y-6">
      {/* -------- Category sub-tabs -------- */}
      <div
        role="tablist"
        aria-label="Artifact category"
        className="flex flex-wrap gap-2 rounded-xl border border-slate-200 bg-white p-2 dark:border-slate-800 dark:bg-slate-900"
      >
        {ARTIFACT_CATEGORIES.map((c) => {
          const isActive = c.id === activeCategoryId
          const CatIcon = c.icon
          const count = totalRecords(endpointData.categories[c.id])
          return (
            <button
              key={c.id}
              type="button"
              role="tab"
              aria-selected={isActive}
              onClick={() => setActiveCategoryId(c.id)}
              className={[
                'inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500',
                isActive
                  ? 'border-cyan-500/60 bg-cyan-50 text-cyan-700 dark:border-cyan-500/50 dark:bg-cyan-500/10 dark:text-cyan-300'
                  : 'border-transparent text-slate-600 hover:bg-slate-50 dark:text-slate-400 dark:hover:bg-slate-800/60',
              ].join(' ')}
            >
              <CatIcon className={`h-4 w-4 ${isActive ? '' : c.accent}`} />
              {c.label}
              {count > 0 && (
                <span
                  className={[
                    'rounded-full px-1.5 text-xs tabular-nums',
                    isActive
                      ? 'bg-cyan-600/20 text-cyan-700 dark:text-cyan-300'
                      : 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400',
                  ].join(' ')}
                >
                  {count.toLocaleString('en-US')}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {/* -------- Sources: per-source collection + import -------- */}
      <Card
        title={`Sources — ${category.label} (${osLabel})`}
        icon={Upload}
        actions={
          <div className="flex items-center gap-2">
            {sources.length > 0 && (
              <Button variant="secondary" size="sm" icon={Sparkles} onClick={handleLoadDemo}>
                Load demo data
              </Button>
            )}
            {hasData && (
              <Button variant="danger" size="sm" icon={Trash2} onClick={() => setConfirmClear(true)}>
                Clear
              </Button>
            )}
          </div>
        }
      >
        {sources.length === 0 ? (
          <div className="flex items-start gap-2 rounded-lg border border-dashed border-slate-300 p-4 text-sm text-slate-500 dark:border-slate-700 dark:text-slate-400">
            <Info className="mt-0.5 h-4 w-4 shrink-0" />
            <span>
              No fully-custom collection method for <strong>{category.label.toLowerCase()}</strong>{' '}
              on {osLabel}: the standard artifacts here require third-party DFIR parsers, so this
              category is empty for this host OS. Switch the incident OS, or use another tab.
            </span>
          </div>
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            {sources.map((source) => {
              const meta = catData.sources?.[source.key]?.meta ?? null
              const isFile = source.mode === 'file'
              return (
                <div
                  key={source.key}
                  className="flex flex-col gap-2 rounded-xl border border-slate-200 p-3 dark:border-slate-800"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-slate-800 dark:text-slate-100">
                      {source.name}
                    </p>
                    <p className="break-all font-mono text-[11px] text-slate-500 dark:text-slate-400">
                      {source.path}
                    </p>
                    {source.tool && (
                      <p className="text-[11px] text-slate-400 dark:text-slate-500">{source.tool}</p>
                    )}
                  </div>

                  {/* Script sources: show the native script to run, then import its CSV. */}
                  {!isFile && source.script && (
                    <details className="group">
                      <summary className="inline-flex cursor-pointer items-center gap-1 text-[11px] font-medium text-cyan-700 hover:underline dark:text-cyan-400">
                        <Terminal className="h-3 w-3" />
                        Collection script ({source.script.lang === 'powershell' ? 'PowerShell' : 'Bash'})
                      </summary>
                      <ScriptBlock
                        script={source.script}
                        filename={`collect-${category.id}-${slugify(source.name)}`}
                      />
                    </details>
                  )}

                  <FileUploadZone
                    label={isFile ? source.name : `${source.name} — CSV`}
                    description={
                      isFile
                        ? 'Upload the existing file from the host (parsed here).'
                        : 'Upload the CSV the script produced.'
                    }
                    icon={category.icon}
                    accept={isFile ? source.accept || '' : '.csv,.json'}
                    meta={meta}
                    loading={!!loading[source.key]}
                    error={errors[source.key] ?? null}
                    onFile={(file) => handleFile(source, file)}
                    onClear={() => clearArtifactSource(incident.id, category.id, source.key)}
                  />
                </div>
              )
            })}
          </div>
        )}
      </Card>

      {/* -------- Combined records table -------- */}
      <ArtifactSection incident={incident} category={category} records={combined} />

      {/* -------- Confirm clear modal -------- */}
      <Modal
        open={confirmClear}
        onClose={() => setConfirmClear(false)}
        title={`Clear ${category.label}`}
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirmClear(false)}>
              Cancel
            </Button>
            <Button variant="danger" icon={Trash2} onClick={handleConfirmClear}>
              Clear
            </Button>
          </>
        }
      >
        <p className="text-sm text-slate-600 dark:text-slate-300">
          You are about to delete all imported <strong>{category.label}</strong> records (every
          source) in the incident <strong>{incident.name}</strong>. Other categories are left
          untouched. This action is irreversible.
        </p>
      </Modal>
    </div>
  )
}
