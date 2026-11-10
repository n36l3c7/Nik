import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  Clock,
  FileJson,
  Flag,
  Info,
  KeyRound,
  ScrollText,
  Sparkles,
  Terminal,
  Trash2,
  TriangleAlert,
  Upload,
  X,
} from 'lucide-react'
import { Badge, Button, Card, DataTable, EmptyState, Modal, StatCard } from '../../ui/index.js'
import FileUploadZone from '../browser/FileUploadZone.jsx'
import ScriptBlock from '../endpoint/ScriptBlock.jsx'
import CoverageChart from './CoverageChart.jsx'
import EventsSection from './EventsSection.jsx'
import EvtxUpload from './EvtxUpload.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { useNavigation } from '../../../context/NavigationContext.jsx'
import { IocValue } from '../../../context/IocLookupContext.jsx'
import { useSocEngine } from '../../../context/SettingsContext.jsx'
import { EVENTLOG_COLLECTION_SCRIPT, EVENT_CHANNELS, LOGON_TYPES, getChannel } from '../../../config/eventLogs.js'
import { getDemoEventLogData } from '../../../services/demoData.js'
import { sha256Hex } from '../../../utils/hash.js'
import { buildEventLogEvents, coverage, logonSessions, parseEventLogJson } from '../../../utils/eventLogs.js'
import { guessIocType } from '../../../utils/iocs.js'
import { computeSocStats } from '../../../utils/soc.js'
import { formatDateTime } from '../../../utils/time.js'

/*
 * "Event Logs" tab (Windows): curated events from the host's event logs.
 *   - raw .evtx files are uploaded and parsed on the server (EvtxUpload);
 *   - or the native collection script exports the same events as JSON, parsed
 *     here in the browser.
 * The tab shows which channels were loaded, how much time each log covers
 * (silences, clears) against the suspicious window, the logon sessions and
 * every event with its SOC verdict. Linux and macOS logs are not covered yet.
 */

const NO_CHANNELS = {}

function formatDuration(ms) {
  if (!Number.isFinite(ms)) return 'open'
  const minutes = Math.round(ms / 60000)
  if (minutes < 60) return `${minutes} min`
  const hours = Math.floor(minutes / 60)
  return hours < 48 ? `${hours} h ${minutes % 60} min` : `${Math.round(hours / 24)} days`
}

const SESSION_COLUMNS = [
  {
    key: 'start',
    label: 'Logon',
    sortable: true,
    sortAccessor: (row) => row.start ?? 0,
    render: (row) => <span className="whitespace-nowrap font-mono text-xs text-fg">{formatDateTime(row.start)}</span>,
  },
  {
    key: 'user',
    label: 'User',
    sortable: true,
    render: (row) => (
      <span className="inline-flex items-center gap-1.5 font-mono text-xs text-fg">
        {row.user}
        {row.elevated && (
          <Badge color="amber" title="Special privileges assigned to the logon (4672)">
            admin
          </Badge>
        )}
      </span>
    ),
  },
  {
    key: 'logonType',
    label: 'Type',
    sortable: true,
    render: (row) => (
      <Badge color={row.logonType === '10' ? 'cyan' : 'slate'}>
        {LOGON_TYPES[row.logonType] ?? `type ${row.logonType}`}
      </Badge>
    ),
  },
  {
    key: 'source',
    label: 'Source',
    sortable: true,
    render: (row) =>
      row.source ? (
        <IocValue type={guessIocType(row.source)} value={row.source} className="font-mono text-xs text-fg" />
      ) : (
        <span className="text-fg-muted">—</span>
      ),
  },
  {
    key: 'end',
    label: 'Logoff',
    sortable: true,
    sortAccessor: (row) => row.end ?? 0,
    render: (row) =>
      row.end ? (
        <span className="whitespace-nowrap font-mono text-xs text-fg-muted">{formatDateTime(row.end)}</span>
      ) : (
        <span className="text-fg-muted">—</span>
      ),
  },
  {
    key: 'durationMs',
    label: 'Duration',
    sortable: true,
    sortAccessor: (row) => row.durationMs ?? Infinity,
    render: (row) => (
      <span className="whitespace-nowrap font-mono text-xs text-fg-muted">{formatDuration(row.durationMs)}</span>
    ),
  },
]

export default function EventLogsTab({ incident }) {
  const engine = useSocEngine()
  const { setEventLogChannels, clearEventLogs, retryActiveIncident } = useIncidents()
  const [jsonLoading, setJsonLoading] = useState(false)
  const [jsonError, setJsonError] = useState(null)
  const [confirmClear, setConfirmClear] = useState(false)

  const channels = incident.data.eventlogs?.channels ?? NO_CHANNELS
  const isWindows = (incident.os ?? 'windows') === 'windows'

  const events = useMemo(() => buildEventLogEvents({ channels, engine }), [channels, engine])
  const stats = useMemo(() => computeSocStats(events), [events])
  const sessions = useMemo(() => logonSessions(events), [events])
  const chart = useMemo(() => coverage(channels, events), [channels, events])
  const flags = incident.flags
  const flaggedCount = useMemo(() => events.reduce((n, e) => n + (flags[e.id] ? 1 : 0), 0), [events, flags])
  const channelOptions = useMemo(
    () => Object.keys(channels).map((name) => ({ value: name, label: getChannel(name)?.short ?? name })),
    [channels],
  )
  const loaded = Object.entries(channels).sort(([a], [b]) => a.localeCompare(b))

  const handleJson = async (file) => {
    setJsonError(null)
    setJsonLoading(true)
    try {
      const [text, sha256] = await Promise.all([file.text(), sha256Hex(file)])
      const parsed = parseEventLogJson(text, file.name)
      for (const slot of Object.values(parsed)) slot.meta.sha256 = sha256
      const kept = Object.values(parsed).reduce((n, slot) => n + slot.events.length, 0)
      setEventLogChannels(incident.id, parsed, {
        action: 'eventlog.upload',
        details: `Imported ${file.name} → ${Object.keys(parsed).join(', ')} (${kept} events)`,
      })
    } catch (err) {
      setJsonError(err?.message ?? 'Unexpected error while parsing the file.')
    } finally {
      setJsonLoading(false)
    }
  }

  // A file dropped anywhere in the app for this tab (see NavigationContext).
  const { requests, take } = useNavigation()
  const [droppedEvtx, setDroppedEvtx] = useState(null)
  useEffect(() => {
    if (!requests.eventlogs) return
    const request = take('eventlogs')
    if (!request?.file) return
    if (request.params?.kind === 'json') handleJson(request.file)
    else setDroppedEvtx({ files: [request.file], at: Date.now() })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requests.eventlogs])

  const handleDemo = () =>
    setEventLogChannels(incident.id, getDemoEventLogData(), {
      action: 'eventlog.demo',
      details: 'Loaded demo event logs',
    })

  return (
    <div className="space-y-6">
      <Card
        title="Sources — Windows event logs"
        icon={Upload}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" icon={Sparkles} onClick={handleDemo}>
              Load demo data
            </Button>
            {loaded.length > 0 && (
              <Button variant="danger" size="sm" icon={Trash2} onClick={() => setConfirmClear(true)}>
                Clear
              </Button>
            )}
          </div>
        }
      >
        {!isWindows && (
          <p className="mb-3 flex items-start gap-2 border border-dashed border-line p-3 text-xs text-fg-muted">
            <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            This incident's host is not Windows. Only Windows event logs are supported for now; journald, auth.log and
            the macOS unified log will follow.
          </p>
        )}
        <div className="grid gap-4 md:grid-cols-2">
          <div className="flex flex-col gap-2 border border-line p-3">
            <div>
              <p className="text-sm font-semibold text-fg">Raw logs (.evtx)</p>
              <p className="text-[11px] text-fg-muted">
                Copy the files from the host (or a disk image) and drop them here. The server keeps the curated event
                ids, recovers records left after a clear and stores the file's SHA-256.
              </p>
            </div>
            <EvtxUpload incidentId={incident.id} onDone={retryActiveIncident} dropped={droppedEvtx} />
          </div>
          <div className="flex flex-col gap-2 border border-line p-3">
            <div>
              <p className="text-sm font-semibold text-fg">Live host (collection script)</p>
              <p className="text-[11px] text-fg-muted">
                Run the native PowerShell script as administrator; it exports the same curated events to
                nik-eventlogs.json, parsed here in the browser.
              </p>
            </div>
            <details>
              <summary className="inline-flex cursor-pointer items-center gap-1 text-[11px] font-medium text-accent hover:underline">
                <Terminal className="h-3 w-3" />
                Collection script (PowerShell)
              </summary>
              <ScriptBlock script={EVENTLOG_COLLECTION_SCRIPT} filename="collect-eventlogs" />
            </details>
            <FileUploadZone
              label="nik-eventlogs.json"
              description="Upload the JSON the script produced."
              icon={FileJson}
              accept=".json"
              loading={jsonLoading}
              error={jsonError}
              onFile={handleJson}
              onClear={() => setJsonError(null)}
            />
          </div>
        </div>

        {loaded.length > 0 && (
          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-fg-muted">
                <tr className="border-b border-line">
                  <th className="px-2 py-1.5 font-medium">Channel</th>
                  <th className="px-2 py-1.5 font-medium">Source</th>
                  <th className="px-2 py-1.5 text-right font-medium">Kept / records</th>
                  <th className="px-2 py-1.5 font-medium">Covers</th>
                  <th className="px-2 py-1.5 font-medium">SHA-256</th>
                  <th className="w-px px-2 py-1.5" />
                </tr>
              </thead>
              <tbody>
                {loaded.map(([name, slot]) => {
                  const meta = slot.meta ?? {}
                  return (
                    <tr key={name} className="border-b border-line-soft">
                      <td className="px-2 py-1.5 text-fg" title={name}>
                        {getChannel(name)?.short ?? name}
                      </td>
                      <td className="px-2 py-1.5">
                        <span className="inline-flex items-center gap-1.5">
                          <Badge color={meta.format === 'evtx' ? 'cyan' : meta.format === 'json' ? 'emerald' : 'slate'}>
                            {String(meta.format ?? '?').toUpperCase()}
                          </Badge>
                          <span className="max-w-[14rem] truncate font-mono text-fg-muted" title={meta.fileName}>
                            {meta.fileName}
                          </span>
                        </span>
                      </td>
                      <td className="whitespace-nowrap px-2 py-1.5 text-right font-mono text-fg">
                        {(slot.events?.length ?? 0).toLocaleString('en-US')} /{' '}
                        {Number(meta.total ?? 0).toLocaleString('en-US')}
                        {meta.recovered > 0 && (
                          <Badge color="violet" className="ml-1.5" title="Records recovered after a clear">
                            +{meta.recovered} recovered
                          </Badge>
                        )}
                        {meta.dropped > 0 && (
                          <span className="ml-1.5 text-med" title="Oldest curated events beyond the per-log cap">
                            ({meta.dropped.toLocaleString('en-US')} older dropped)
                          </span>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-2 py-1.5 font-mono text-fg-muted">
                        {Number.isFinite(meta.first)
                          ? `${formatDateTime(meta.first)} → ${formatDateTime(meta.last)}`
                          : '—'}
                      </td>
                      <td className="px-2 py-1.5 font-mono text-fg-muted" title={meta.sha256}>
                        {meta.sha256 ? `${meta.sha256.slice(0, 12)}…` : '—'}
                      </td>
                      <td className="px-2 py-1.5">
                        <button
                          type="button"
                          aria-label={`Remove ${name}`}
                          title="Remove this log"
                          onClick={() => clearEventLogs(incident.id, name)}
                          className="p-1 text-fg-muted hover:bg-high-soft hover:text-high focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                        >
                          <X className="h-3.5 w-3.5" />
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        <p className="mt-3 text-[11px] text-fg-subtle">
          Channels read: {EVENT_CHANNELS.map((c) => c.short).join(' · ')}. Other logs are counted, not stored.
        </p>
      </Card>

      {events.length === 0 && loaded.length === 0 ? (
        <EmptyState
          icon={ScrollText}
          title="No event logs yet"
          message="Upload .evtx files or the script's JSON above, or use 'Load demo data' to explore the platform."
        />
      ) : (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard icon={ScrollText} label="Events kept" value={stats.total} />
            <StatCard
              icon={TriangleAlert}
              label="SOC detections"
              value={stats.flagged}
              tone={stats.flagged > 0 ? 'accent' : 'default'}
              hint={stats.high > 0 ? `${stats.high} high-severity` : undefined}
            />
            <StatCard icon={KeyRound} label="Logon sessions" value={sessions.length} />
            <StatCard icon={Flag} label="Flagged" value={flaggedCount} tone={flaggedCount > 0 ? 'accent' : 'default'} />
          </div>

          <Card title="Log coverage" icon={Activity}>
            <CoverageChart data={chart} windowStart={incident.suspiciousStart} windowEnd={incident.suspiciousEnd} />
          </Card>

          {sessions.length > 0 && (
            <Card title="Logon sessions" icon={Clock}>
              <p className="mb-2 text-[11px] text-fg-muted">
                Each logon (4624) paired with its logoff (4634/4647) and admin privileges (4672) by logon id. Service
                logons and machine accounts are left out.
              </p>
              <DataTable
                columns={SESSION_COLUMNS}
                data={sessions}
                searchKeys={['user', 'source', 'logonId']}
                searchPlaceholder="Search users, sources…"
                defaultSort={{ key: 'start', dir: 'desc' }}
                defaultPageSize={10}
                rowClassName={(row) =>
                  row.severity === 'high'
                    ? 'bg-high-soft border-l-2 border-l-high-line'
                    : row.severity === 'medium'
                      ? 'bg-med-soft border-l-2 border-l-med-line'
                      : ''
                }
              />
            </Card>
          )}

          <EventsSection incident={incident} events={events} channelOptions={channelOptions} />
        </>
      )}

      <Modal
        open={confirmClear}
        onClose={() => setConfirmClear(false)}
        title="Clear event logs"
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirmClear(false)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              icon={Trash2}
              onClick={() => {
                clearEventLogs(incident.id)
                setConfirmClear(false)
              }}
            >
              Clear
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg-muted">
          You are about to delete every imported event log of the incident <strong>{incident.name}</strong>. Flags on
          these events stay in the Summary. This action is irreversible.
        </p>
      </Modal>
    </div>
  )
}
