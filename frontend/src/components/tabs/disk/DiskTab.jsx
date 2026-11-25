import { useCallback, useEffect, useMemo, useState } from 'react'
import { Clock, Database, Flag, HelpCircle, Info, ListTree, ShieldAlert, Trash2 } from 'lucide-react'
import { Button, Modal, StatCard, Tabs, tabId } from '../../ui/index.js'
import SourceFiles from '../../evidence/SourceFiles.jsx'
import SourceViewer from '../../evidence/SourceViewer.jsx'
import DetectionsSection from '../../evidence/DetectionsSection.jsx'
import { MftTable, UsnTable } from './DiskTables.jsx'
import { useAuth } from '../../../context/AuthContext.jsx'
import { detectionTone, levelsText } from '../../../domain/detections.js'
import {
  DISK_KIND,
  DISK_SOURCES,
  deletedFilters,
  diskItems,
  diskSourceById,
  expectedDiskFile,
} from '../../../domain/diskPage.js'
import { countsBySource } from '../../../domain/endpointPage.js'
import { formatDate } from '../../../lib/time.js'
import { useDetections } from '../../../lib/useDetections.js'
import { evidence } from '../../../services/api.js'

/*
 * "Disk (NTFS)": the $MFT and the $J (USN journal) of a volume, read by the worker. Two selector tabs choose
 * which; the files (with where to find each), the counts, the table and the detections follow the one chosen.
 * The tables hold millions of rows and are only ever paged by the server (DiskTables.jsx).
 */

const NO_SOURCES = []
const SECTIONS = [
  { id: 'entries', label: 'Records' },
  { id: 'detections', label: 'Detections' },
]

function Help() {
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button variant="ghost" size="xs" icon={HelpCircle} onClick={() => setOpen(true)}>
        Where to find these files
      </Button>
      <Modal open={open} onClose={() => setOpen(false)} title="Where to find the $MFT and the $J" maxWidth="max-w-3xl">
        <div className="space-y-4 text-sm text-fg-muted">
          {DISK_SOURCES.map((item) => (
            <section key={item.id} className="space-y-1">
              <p className="font-semibold text-fg">{item.label}</p>
              <p className="break-words font-mono text-xs">{item.hint}</p>
            </section>
          ))}
        </div>
      </Modal>
    </>
  )
}

const number = (n) => Number(n || 0).toLocaleString('en-US')

export default function DiskTab({ incident }) {
  const { can } = useAuth()
  const archived = Boolean(incident.archivedAt)
  const canWrite = can('write') && !archived
  const [tab, setTab] = useState(DISK_SOURCES[0].id)
  const [version, setVersion] = useState(0)
  const [sources, setSources] = useState(NO_SOURCES)
  const [counts, setCounts] = useState(null) // records per source name, from the server
  const [stats, setStats] = useState({ deleted: null, from: null, to: null, flagged: null })
  const [part, setPart] = useState('entries')
  const [focusRule, setFocusRule] = useState('')
  const [ruleTitles, setRuleTitles] = useState({})
  const [fileView, setFileView] = useState(null)
  const changed = useCallback(() => setVersion((n) => n + 1), [])

  const item = diskSourceById(tab)
  const base = useMemo(() => ({ kind: DISK_KIND, source: item.key }), [item.key])

  // The counts of the selector and the files (for the dots and the viewer): the server's.
  useEffect(() => {
    const controller = new AbortController()
    const { signal } = controller
    evidence
      .sources(incident.id, { kind: DISK_KIND, signal })
      .then((answer) => setSources(answer.sources))
      .catch(() => {})
    if (archived) setCounts({})
    else
      evidence
        .stack(incident.id, { field: 'source', filters: { kind: DISK_KIND }, limit: 100, signal })
        .then((answer) => setCounts(countsBySource(answer.values)))
        .catch(() => setCounts((held) => held ?? {}))
    return () => controller.abort()
  }, [incident.id, archived, version])

  const total = Object.values(counts ?? {}).reduce((sum, n) => sum + n, 0)
  const here = counts?.[item.key] ?? 0

  // The cards of the tab chosen: deleted entries (a $MFT only), the time it spans and what is flagged.
  useEffect(() => {
    if (archived || here === 0) return undefined
    const controller = new AbortController()
    const { signal } = controller
    const quiet = () => null
    Promise.all([
      item.id === 'mft'
        ? evidence.records(incident.id, { filters: deletedFilters(base), limit: 1, signal }).catch(quiet)
        : null,
      evidence.histogram(incident.id, { filters: base, buckets: 10, signal }).catch(quiet),
      evidence.records(incident.id, { filters: { ...base, flagged: true }, limit: 1, signal }).catch(quiet),
    ]).then(([deleted, span, flagged]) => {
      if (signal.aborted) return
      setStats({
        deleted: deleted ? deleted.count : null,
        from: span?.from ?? null,
        to: span?.to ?? null,
        flagged: flagged?.count ?? null,
      })
    })
    return () => controller.abort()
  }, [incident.id, archived, here, item.id, base, version])

  const found = useDetections(incident.id, {
    kind: DISK_KIND,
    source: item.key,
    refresh: version,
    enabled: !archived && here > 0,
  })
  const items = useMemo(() => diskItems(counts ?? {}, sources), [counts, sources])
  const expected = useMemo(() => expectedDiskFile(item.id), [item.id])
  const keep = useCallback((source) => source.source === item.key, [item.key])
  const match = useCallback((source) => (source.source === item.key ? item.key : null), [item.key])
  // The time the records span, in days with the dates under it: a card is not wide enough for two date-times.
  const days =
    stats.from != null && stats.to != null ? Math.max(1, Math.round((stats.to - stats.from) / 86_400_000)) : null
  const span = days === null ? '—' : `${days.toLocaleString('en-US')} day${days === 1 ? '' : 's'}`
  const spanDates = days === null ? undefined : `${formatDate(stats.from)} – ${formatDate(stats.to)}`

  const openRule = useCallback((rule) => {
    setRuleTitles((before) => ({ ...before, [rule.ruleId]: rule.title }))
    setFocusRule(rule.ruleId)
    setPart('entries')
  }, [])

  return (
    <div className="space-y-6">
      <Tabs variant="selector" label="Disk files" idPrefix="disk" items={items} value={item.id} onChange={setTab} />

      <div role="tabpanel" aria-labelledby={tabId('disk', item.id)} className="space-y-6">
        {archived && (
          <p role="status" className="flex items-start gap-2 border border-line bg-panel p-3 text-sm text-fg-muted">
            <Info className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
            Archived: the records are not loaded. Take the incident out of the archive to read them again.
          </p>
        )}
        <SourceFiles
          incidentId={incident.id}
          kind={DISK_KIND}
          filter={keep}
          expected={expected}
          match={match}
          title={`Sources — ${item.label}`}
          help={<Help />}
          canWrite={canWrite}
          onChanged={changed}
          onView={setFileView}
        />

        {!archived && counts !== null && here > 0 && (
          <>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
              <StatCard
                icon={ListTree}
                label={item.id === 'mft' ? 'Entries' : 'Journal records'}
                value={number(here)}
              />
              {item.id === 'mft' && (
                <StatCard
                  icon={Trash2}
                  label="Deleted"
                  value={stats.deleted === null ? '—' : number(stats.deleted)}
                  tone={stats.deleted > 0 ? 'warn' : 'default'}
                />
              )}
              <StatCard icon={Clock} label="Time span" value={span} hint={spanDates} />
              <StatCard icon={Database} label="Disk records" value={number(total)} hint="$MFT and $J together" />
              <StatCard
                icon={Flag}
                label="Flagged"
                value={stats.flagged === null ? '—' : number(stats.flagged)}
                tone={stats.flagged > 0 ? 'accent' : 'default'}
              />
              <StatCard
                icon={ShieldAlert}
                label="Detections"
                value={number(found.data.detections)}
                tone={detectionTone(found.data.byLevel)}
                hint={levelsText(found.data.byLevel) || undefined}
              />
            </div>

            <div className="space-y-3">
              <Tabs
                variant="section"
                label="Parts of the disk page"
                idPrefix="disk-part"
                items={SECTIONS.map((section) => ({
                  ...section,
                  count: section.id === 'entries' ? here : found.data.total,
                }))}
                value={part}
                onChange={(id) => {
                  setFocusRule('')
                  setPart(id)
                }}
              />
              {part === 'detections' && (
                <DetectionsSection
                  data={found.data}
                  loading={found.loading}
                  error={found.error}
                  onOpen={openRule}
                  noun="records"
                />
              )}
              {part === 'entries' &&
                (item.id === 'mft' ? (
                  <MftTable
                    key={`${incident.id}:${focusRule}`}
                    incident={incident}
                    sources={sources}
                    canWrite={canWrite}
                    refresh={version}
                    focusRule={focusRule}
                    ruleTitles={ruleTitles}
                  />
                ) : (
                  <UsnTable
                    key={`${incident.id}:${focusRule}`}
                    incident={incident}
                    sources={sources}
                    canWrite={canWrite}
                    refresh={version}
                    focusRule={focusRule}
                    ruleTitles={ruleTitles}
                  />
                ))}
            </div>
          </>
        )}
      </div>

      {fileView && <SourceViewer incidentId={incident.id} source={fileView} onClose={() => setFileView(null)} />}
    </div>
  )
}
