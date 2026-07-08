import { useEffect, useMemo, useState } from 'react'
import { FolderInput, Sparkles, Trash2, Upload } from 'lucide-react'
import { Button, Card, Modal } from '../../ui/index.js'
import FileUploadZone from '../browser/FileUploadZone.jsx'
import ArtifactSection from './ArtifactSection.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { parseArtifactFile } from '../../../services/artifactParsers.js'
import { getDemoArtifactData } from '../../../services/demoData.js'
import {
  ARTIFACT_CATEGORIES,
  getArtifactCategoryById,
  buildDefaultArtifactData,
  artifactSourcesFor,
} from '../../../config/artifacts.js'
import { getOsById, DEFAULT_OS } from '../../../config/os.js'

/*
 * "Endpoint Artifacts" tab: one SUB-TAB per forensic category (Program
 * Execution, Persistence, File & Folder Access, USB & Devices), mirroring the
 * Browser Forensics and Command History tabs. Each category imports a CSV/JSON
 * export (the format DFIR tools produce) into a flaggable table with SOC
 * detection. The "where to find it / how to export it" guidance is driven by
 * the incident's host OS.
 */

export default function EndpointArtifactsTab({ incident }) {
  const { updateArtifactData, clearArtifactData } = useIncidents()

  const [activeCategoryId, setActiveCategoryId] = useState(ARTIFACT_CATEGORIES[0].id)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [confirmClear, setConfirmClear] = useState(false)

  const endpointData = incident.data.endpoint
  const os = getOsById(incident.os) ? incident.os : DEFAULT_OS
  const osLabel = getOsById(os)?.label ?? os

  const category = getArtifactCategoryById(activeCategoryId) ?? ARTIFACT_CATEGORIES[0]
  const current = endpointData.categories[activeCategoryId] ?? buildDefaultArtifactData()
  const meta = current.meta ?? null
  const hasData = (current.records?.length ?? 0) > 0

  const sources = useMemo(() => artifactSourcesFor(category, os), [category, os])

  useEffect(() => {
    setError(null)
    setLoading(false)
  }, [activeCategoryId, incident.id])

  const handleFile = async (file) => {
    setError(null)
    setLoading(true)
    try {
      const { records, format } = await parseArtifactFile(file, category)
      updateArtifactData(
        incident.id,
        activeCategoryId,
        {
          records,
          meta: {
            fileName: file.name,
            format,
            rows: records.length,
            importedAt: new Date().toISOString(),
          },
        },
        {
          action: 'endpoint.upload',
          details: `Imported ${category.label} (${records.length} records)`,
        },
      )
    } catch (err) {
      setError(err?.message ?? 'Unexpected error while parsing the file.')
    } finally {
      setLoading(false)
    }
  }

  const handleLoadDemo = () => {
    const demo = getDemoArtifactData(category, os)
    setError(null)
    updateArtifactData(
      incident.id,
      activeCategoryId,
      {
        records: demo.records,
        meta: {
          fileName: 'Demo data',
          format: 'demo',
          rows: demo.records.length,
          importedAt: new Date().toISOString(),
        },
      },
      { action: 'endpoint.demo', details: `Loaded demo ${category.label}` },
    )
  }

  const handleConfirmClear = () => {
    clearArtifactData(incident.id, activeCategoryId)
    setError(null)
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
          const count = endpointData.categories[c.id]?.records?.length ?? 0
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

      {/* -------- OS-aware "where to find it / how to export" note -------- */}
      {!meta && (
        <div className="flex gap-3 rounded-xl border border-cyan-200 bg-cyan-50/60 p-4 text-sm dark:border-cyan-500/30 dark:bg-cyan-500/5">
          <FolderInput className="mt-0.5 h-5 w-5 shrink-0 text-cyan-600 dark:text-cyan-400" />
          <div className="min-w-0 space-y-1.5">
            <p className="font-medium text-slate-700 dark:text-slate-200">
              {category.label} sources on {osLabel} — export to CSV/JSON, then import here
            </p>
            <ul className="space-y-1">
              {sources.map((source) => (
                <li key={source.name} className="text-xs text-slate-600 dark:text-slate-400">
                  <span className="font-medium">{source.name}:</span>{' '}
                  <span className="break-all font-mono text-[11px] text-slate-500 dark:text-slate-400">
                    {source.path}
                  </span>
                  {source.tool && (
                    <span className="text-slate-400 dark:text-slate-500"> — {source.tool}</span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* -------- Data source card -------- */}
      <Card
        title={`Data source — ${category.label}`}
        icon={Upload}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" icon={Sparkles} onClick={handleLoadDemo}>
              Load demo data
            </Button>
            {hasData && (
              <Button variant="danger" size="sm" icon={Trash2} onClick={() => setConfirmClear(true)}>
                Clear
              </Button>
            )}
          </div>
        }
      >
        <div className="grid gap-4 md:grid-cols-1">
          <FileUploadZone
            label={`${category.label} export`}
            description="CSV (with a header row) or JSON array from your DFIR tool."
            icon={category.icon}
            accept=".csv,.json,.tsv,.txt"
            pathHint={sources[0]?.path ?? null}
            meta={meta}
            loading={loading}
            error={error}
            onFile={handleFile}
            onClear={() => clearArtifactData(incident.id, activeCategoryId)}
          />
        </div>
      </Card>

      {/* -------- Records section -------- */}
      <ArtifactSection incident={incident} category={category} records={current.records} />

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
          You are about to delete all imported <strong>{category.label}</strong> records in the
          incident <strong>{incident.name}</strong>. Other categories are left untouched. This action
          is irreversible.
        </p>
      </Modal>
    </div>
  )
}
