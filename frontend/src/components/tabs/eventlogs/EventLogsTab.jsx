import { useCallback, useEffect, useMemo, useState } from 'react'
import { Activity, FileSearch, Flag, HelpCircle, Info, ScrollText, Server, ShieldAlert, Terminal } from 'lucide-react'
import { Button, Card, Modal, StatCard, Tabs } from '../../ui/index.js'
import SourceFiles from '../../evidence/SourceFiles.jsx'
import DetectionsSection from '../../evidence/DetectionsSection.jsx'
import LogonsSection from './LogonsSection.jsx'
import ProcessesSection from './ProcessesSection.jsx'
import ScriptBlock from '../endpoint/ScriptBlock.jsx'
import CoverageChart from './CoverageChart.jsx'
import SyslogLogs from './SyslogLogs.jsx'
import EventsSection from './EventsSection.jsx'
import { useAuth } from '../../../context/AuthContext.jsx'
import { normalizeOs } from '../../../config/os.js'
import { EVENTLOG_COLLECTION_SCRIPT, EVENT_CHANNELS } from '../../../config/eventLogs.js'
import {
  EVENTLOG_KIND,
  EXPECTED_CHANNELS,
  channelsLabel,
  coverageRows,
  matchSource,
} from '../../../domain/eventLogSources.js'
import { detectionTone, levelsText } from '../../../domain/detections.js'
import { hostCounts } from '../../../domain/evidence.js'
import { logFamilies } from '../../../domain/syslogSources.js'
import { useEvidenceSummary } from '../../../lib/useEvidenceSummary.js'
import { useDetections } from '../../../lib/useDetections.js'
import { evidence } from '../../../services/api.js'

/*
 * "Event Logs" tab (Windows): the host's event logs, read by the worker.
 *   - raw .evtx files and the collection script's nik-eventlogs.json are sent to the server in parts
 *     (SourceFiles); the worker keeps every event and writes a report of what it read of each file;
 *   - the events are read from the server a page at a time (EventsSection).
 * Detections (the Sigma rules that matched events) is the second part; processes and logons come as more
 * section tabs: one item of SECTIONS each.
 * The logs of Linux and macOS are the page of SyslogLogs.jsx; this file picks the one that fits the incident's
 * system (both when it names none, as two tabs).
 */

const NO_SOURCES = []

/** The parts of the page, as Tabs items; `count` is filled from the server. */
const SECTIONS = [
  { id: 'events', label: 'Events' },
  { id: 'detections', label: 'Detections' },
  { id: 'processes', label: 'Processes' },
  { id: 'logons', label: 'Logons' },
]

function Help() {
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button variant="ghost" size="xs" icon={HelpCircle} onClick={() => setOpen(true)}>
        Where to find these files
      </Button>
      <Modal open={open} onClose={() => setOpen(false)} title="Where to find the event logs" maxWidth="max-w-3xl">
        <div className="space-y-4 text-sm text-fg-muted">
          <section className="space-y-1">
            <p className="font-semibold text-fg">Raw logs (.evtx)</p>
            <p>
              Copy the files from the host (or a disk image) and add them here. They are in{' '}
              <code className="font-mono text-fg">C:\Windows\System32\winevt\Logs</code>. The server keeps the original
              and its SHA-256, reads every event, and recovers records left after a clear.
            </p>
            <p className="font-mono text-xs">Channels Nik names: {EVENT_CHANNELS.map((c) => c.short).join(' · ')}.</p>
          </section>
          <section className="space-y-2">
            <p className="font-semibold text-fg">Live host (collection script)</p>
            <p>
              Run the native PowerShell script as administrator; it exports the curated events to nik-eventlogs.json,
              which you add here like an .evtx file.
            </p>
            <p className="inline-flex items-center gap-1 text-xs font-medium text-accent">
              <Terminal className="h-3 w-3" aria-hidden="true" />
              Collection script (PowerShell)
            </p>
            <ScriptBlock script={EVENTLOG_COLLECTION_SCRIPT} filename="collect-eventlogs" />
          </section>
        </div>
      </Modal>
    </>
  )
}

function WindowsLogs({ incident }) {
  const { can } = useAuth()
  const archived = Boolean(incident.archivedAt)
  const canWrite = can('write') && !archived
  const [version, setVersion] = useState(0)
  const [sources, setSources] = useState(NO_SOURCES)
  const [counts, setCounts] = useState({
    records: 0,
    sources: 0,
    channels: 0,
    flagged: 0,
    matter: 0,
    processes: 0,
    logons: 0,
  })
  const [matter, setMatter] = useState(true) // "Events that matter": on until the person asks for all
  const [section, setSection] = useState(SECTIONS[0].id)
  const [focusRule, setFocusRule] = useState('') // a rule opened from Detections: Events shows only its events
  const [ruleTitles, setRuleTitles] = useState({}) // rule id -> title, for the chip of the filter
  const changed = useCallback(() => setVersion((n) => n + 1), [])

  // What the page shows above the table: the files, and the counts of the server.
  useEffect(() => {
    const controller = new AbortController()
    const { signal } = controller
    const filters = { kind: EVENTLOG_KIND }
    const quiet = () => null
    Promise.all([
      evidence.sources(incident.id, { kind: EVENTLOG_KIND, signal }).catch(quiet),
      evidence.summary(incident.id, { signal }).catch(quiet),
      archived ? null : evidence.stack(incident.id, { field: 'channel', limit: 1, filters, signal }).catch(quiet),
      archived
        ? null
        : evidence.records(incident.id, { filters: { ...filters, flagged: true }, limit: 1, signal }).catch(quiet),
      archived
        ? null
        : evidence.records(incident.id, { filters: { ...filters, matter: true }, limit: 1, signal }).catch(quiet),
    ]).then(([listed, summary, channels, flagged, mattering]) => {
      if (signal.aborted) return
      if (listed) setSources(listed.sources)
      const mine = summary?.kinds?.[EVENTLOG_KIND]
      setCounts((before) => ({
        records: mine?.records ?? before.records,
        sources: mine?.sources ?? before.sources,
        channels: channels?.distinct ?? before.channels,
        flagged: flagged?.count ?? before.flagged,
        matter: mattering?.count ?? before.matter,
        processes: mine?.processes ?? before.processes,
        logons: mine?.logons ?? before.logons,
      }))
    })
    return () => controller.abort()
  }, [incident.id, archived, version])

  const chart = useMemo(() => coverageRows(sources), [sources])
  const hasRecords = counts.records > 0
  const found = useDetections(incident.id, { kind: EVENTLOG_KIND, refresh: version, enabled: !archived && hasRecords })
  const openRule = useCallback((rule) => {
    setRuleTitles((before) => ({ ...before, [rule.ruleId]: rule.title }))
    setFocusRule(rule.ruleId)
    setMatter(false) // the events of a rule are not all "events that matter"
    setSection('events')
  }, [])
  const items = SECTIONS.map((item) => ({
    ...item,
    count: {
      events: matter ? counts.matter : counts.records,
      detections: found.data.total,
      processes: counts.processes,
      logons: counts.logons,
    }[item.id],
  }))

  return (
    <div className="space-y-6">
      {archived && (
        <p role="status" className="flex items-start gap-2 border border-line bg-panel p-3 text-sm text-fg-muted">
          <Info className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          Archived: the records are not loaded. Take the incident out of the archive to read them again.
        </p>
      )}
      <SourceFiles
        incidentId={incident.id}
        kind={EVENTLOG_KIND}
        title="Sources — Windows event logs"
        expected={EXPECTED_CHANNELS}
        match={matchSource}
        labelOf={channelsLabel}
        accept=".evtx,.json"
        canWrite={canWrite}
        onChanged={changed}
        help={<Help />}
      />

      {!archived && hasRecords && (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
            <StatCard icon={ScrollText} label="Events kept" value={counts.records.toLocaleString('en-US')} />
            <StatCard icon={FileSearch} label="Sources" value={counts.sources.toLocaleString('en-US')} />
            <StatCard icon={Server} label="Channels" value={counts.channels.toLocaleString('en-US')} />
            <StatCard
              icon={Flag}
              label="Flagged"
              value={counts.flagged.toLocaleString('en-US')}
              tone={counts.flagged > 0 ? 'accent' : 'default'}
            />
            <StatCard
              icon={ShieldAlert}
              label="Detections"
              value={found.data.detections.toLocaleString('en-US')}
              tone={detectionTone(found.data.byLevel)}
              hint={levelsText(found.data.byLevel) || undefined}
            />
          </div>

          {chart.rows.length > 0 && (
            <Card title="Log coverage" icon={Activity}>
              <CoverageChart data={chart} windowStart={incident.suspiciousStart} windowEnd={incident.suspiciousEnd} />
            </Card>
          )}

          <div className="space-y-3">
            <Tabs
              variant="section"
              label="Parts of the event logs"
              idPrefix="eventlogs"
              items={items}
              value={section}
              onChange={(id) => {
                setFocusRule('')
                setSection(id)
              }}
            />
            {section === 'detections' && (
              <DetectionsSection
                data={found.data}
                loading={found.loading}
                error={found.error}
                onOpen={openRule}
                noun="events"
              />
            )}
            {section === 'processes' && <ProcessesSection incident={incident} sources={sources} reload={version} />}
            {section === 'logons' && <LogonsSection incident={incident} sources={sources} reload={version} />}
            {section === 'events' && (
              <EventsSection
                incident={incident}
                sources={sources}
                canWrite={canWrite}
                refresh={version}
                matter={matter}
                onMatterChange={setMatter}
                focusRule={focusRule}
                ruleTitles={ruleTitles}
              />
            )}
          </div>
        </>
      )}
    </div>
  )
}

const FAMILIES = [
  { id: 'windows', label: 'Windows' },
  { id: 'syslog', label: 'Linux and macOS' },
]

/** The event logs of the incident's system: Windows as it was, Linux and macOS from 7.0. */
export default function EventLogsTab({ incident }) {
  const os = normalizeOs(incident.os)
  const families = logFamilies(os)
  const { summary } = useEvidenceSummary(incident.id)
  const [chosen, setChosen] = useState('')
  if (!families.syslog) return <WindowsLogs incident={incident} />
  if (!families.windows) return <SyslogLogs incident={incident} os={os} />
  // No system said: both groups, the one that has records first.
  const windows = summary?.kinds?.eventlog?.sources ?? 0
  const syslog = hostCounts(summary, 'eventlogs').sources - windows
  const family = chosen || (syslog > 0 && windows === 0 ? 'syslog' : 'windows')
  const items = FAMILIES.map((item) => ({ ...item, count: item.id === 'windows' ? windows : syslog }))
  return (
    <div className="space-y-6">
      <Tabs
        variant="selector"
        label="Logs of"
        idPrefix="eventlogs-family"
        items={items}
        value={family}
        onChange={setChosen}
      />
      {family === 'windows' ? <WindowsLogs incident={incident} /> : <SyslogLogs incident={incident} os="" />}
    </div>
  )
}
