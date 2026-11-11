import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Bookmark,
  CalendarClock,
  CircleDot,
  FileText,
  Flag,
  Gauge,
  HardDrive,
  Hash,
  ListTree,
  MonitorCog,
  Save,
  Server,
  StickyNote,
  Terminal,
  Type,
  User,
  UserCheck,
} from 'lucide-react'
import { Button, Card, StatCard } from '../../ui/index.js'
import IncidentTimeline from './IncidentTimeline.jsx'
import OsPicker from '../../layout/OsPicker.jsx'
import { useIncidents, deriveIncidentName } from '../../../context/IncidentContext.jsx'
import { BROWSERS } from '../../../config/browsers.js'
import { SHELLS } from '../../../config/shells.js'
import { ARTIFACT_CATEGORIES } from '../../../config/artifacts.js'
import { normalizeOs } from '../../../config/os.js'
import { SEVERITIES, STATUSES } from '../../../domain/incidentName.js'
import { formatDateTime } from '../../../lib/time.js'

/*
 * ============================================================================
 * SUMMARY TAB
 * ============================================================================
 *
 * The incident's home screen. It offers three things:
 *   1. Editable incident details (ticket ID, short title, severity, status, assignee, host,
 *      username, OS, suspicious start/end) saved
 *      through updateIncidentMeta.
 *   2. A recap row of StatCards computed from the incident's data.
 *   3. The vertical incident timeline (flags + notes).
 */

/* ---- datetime-local helpers (local time, `YYYY-MM-DDTHH:mm`) ---- */

/** Unix ms → value for an <input type="datetime-local"> (local time). */
function msToLocalInput(ms) {
  if (!Number.isFinite(ms)) return ''
  const d = new Date(ms)
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/** <input type="datetime-local"> value → Unix ms (local time), or null. */
function localInputToMs(value) {
  if (!value) return null
  const ms = new Date(value).getTime()
  return Number.isFinite(ms) ? ms : null
}

// Shared class strings for the editable form fields.
const INPUT_CLASS =
  'w-full border border-line bg-panel px-3 py-2 text-sm text-fg ' +
  'placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ' +
  ''

// datetime-local additionally needs its native picker to follow the theme.
const DATETIME_CLASS = `${INPUT_CLASS} [color-scheme:light]`

export default function SummaryTab({ incident }) {
  const { updateIncidentMeta, assignees } = useIncidents()

  /* ---- editable draft, reseeded whenever the active incident changes ---- */
  const [ticketId, setTicketId] = useState(incident.ticketId ?? '')
  const [title, setTitle] = useState(incident.title ?? '')
  const [severity, setSeverity] = useState(incident.severity ?? '')
  const [status, setStatus] = useState(incident.status ?? 'open')
  const [assignee, setAssignee] = useState(incident.assignee ?? '')
  const [host, setHost] = useState(incident.host)
  const [username, setUsername] = useState(incident.username)
  const [os, setOs] = useState(normalizeOs(incident.os))
  const [start, setStart] = useState(msToLocalInput(incident.suspiciousStart))
  const [end, setEnd] = useState(msToLocalInput(incident.suspiciousEnd))

  useEffect(() => {
    // Only reset the draft on a genuine incident switch — not on every save
    // (which bumps updatedAt but keeps the same id), so typed edits survive.
    setTicketId(incident.ticketId ?? '')
    setTitle(incident.title ?? '')
    setSeverity(incident.severity ?? '')
    setStatus(incident.status ?? 'open')
    setAssignee(incident.assignee ?? '')
    setHost(incident.host)
    setUsername(incident.username)
    setOs(normalizeOs(incident.os))
    setStart(msToLocalInput(incident.suspiciousStart))
    setEnd(msToLocalInput(incident.suspiciousEnd))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incident.id])

  // The status and the assignee also change from the panel's menu: follow them.
  useEffect(() => {
    setStatus(incident.status ?? 'open')
    setAssignee(incident.assignee ?? '')
  }, [incident.status, incident.assignee])

  const startMs = localInputToMs(start)
  const endMs = localInputToMs(end)
  // Warn (but do not block) when the suspicious window is inverted.
  const invertedRange = startMs !== null && endMs !== null && endMs < startMs

  const handleSave = () => {
    updateIncidentMeta(incident.id, {
      ticketId,
      title,
      severity: severity || null,
      status,
      assignee,
      host,
      username,
      os,
      suspiciousStart: startMs,
      suspiciousEnd: endMs,
    })
  }

  /* ---- recap figures across every browser and shell ---- */
  const recap = useMemo(() => {
    const browsers = incident.data?.browser?.browsers ?? {}
    let events = 0
    let bookmarks = 0
    for (const b of BROWSERS) {
      for (const profile of Object.values(browsers[b.id]?.profiles ?? {})) {
        events += (profile.history?.length ?? 0) + (profile.downloads?.length ?? 0)
        bookmarks += profile.bookmarks?.length ?? 0
      }
    }
    const shells = incident.data?.commands?.shells ?? {}
    let commands = 0
    for (const s of SHELLS) commands += shells[s.id]?.commands?.length ?? 0
    const cats = incident.data?.endpoint?.categories ?? {}
    let artifacts = 0
    for (const c of ARTIFACT_CATEGORIES) {
      for (const s of Object.values(cats[c.id]?.sources ?? {})) {
        artifacts += s?.records?.length ?? 0
      }
    }
    return { events, bookmarks, commands, artifacts }
  }, [incident.data])

  const flaggedCount = Object.keys(incident.flags ?? {}).length
  const notesCount = incident.notes?.length ?? 0
  const namePreview = deriveIncidentName({ ticketId, title, host, username })

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      {/* ---- 1. Incident details ---- */}
      <Card title="Incident details" icon={FileText}>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field id="incident-ticket" label="Ticket ID" icon={Hash}>
            <input
              id="incident-ticket"
              type="text"
              value={ticketId}
              onChange={(e) => setTicketId(e.target.value)}
              placeholder="e.g. INC-2041"
              className={INPUT_CLASS}
            />
          </Field>

          <Field id="incident-severity" label="Severity" icon={Gauge}>
            <select
              id="incident-severity"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className={INPUT_CLASS}
            >
              <option value="">—</option>
              {SEVERITIES.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </select>
          </Field>

          <Field id="incident-status" label="Status" icon={CircleDot}>
            <select
              id="incident-status"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className={INPUT_CLASS}
            >
              {STATUSES.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </select>
          </Field>

          <Field id="incident-assignee" label="Assigned to" icon={UserCheck}>
            <select
              id="incident-assignee"
              value={assignee}
              onChange={(e) => setAssignee(e.target.value)}
              className={INPUT_CLASS}
            >
              <option value="">nobody</option>
              {[...new Set([...assignees, assignee].filter(Boolean))].map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </Field>

          <div className="sm:col-span-2">
            <Field id="incident-title" label="Short title (replaces host and user in the name)" icon={Type}>
              <input
                id="incident-title"
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="e.g. Invoice phishing, finance"
                className={INPUT_CLASS}
              />
            </Field>
          </div>

          <Field id="incident-host" label="Host" icon={Server}>
            <input
              id="incident-host"
              type="text"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="e.g. WKS-042"
              className={INPUT_CLASS}
            />
          </Field>

          <Field id="incident-username" label="Username" icon={User}>
            <input
              id="incident-username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. j.doe"
              className={INPUT_CLASS}
            />
          </Field>

          <div className="sm:col-span-2">
            <span className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-fg-muted">
              <MonitorCog className="h-3.5 w-3.5" aria-hidden="true" />
              Host operating system
            </span>
            <OsPicker value={os} onChange={setOs} idPrefix="summary-os" />
          </div>

          <Field id="incident-start" label="Suspicious activity — start" icon={CalendarClock}>
            <input
              id="incident-start"
              type="datetime-local"
              value={start}
              onChange={(e) => setStart(e.target.value)}
              className={DATETIME_CLASS}
            />
          </Field>

          <Field id="incident-end" label="Suspicious activity — end" icon={CalendarClock}>
            <input
              id="incident-end"
              type="datetime-local"
              value={end}
              onChange={(e) => setEnd(e.target.value)}
              className={DATETIME_CLASS}
            />
          </Field>
        </div>

        {/* Derived display name preview */}
        <p className="mt-4 text-xs text-fg-muted">
          Display name: <span className="font-medium text-fg">{namePreview}</span>
        </p>

        {/* Inverted-window warning */}
        {invertedRange && (
          <p className="mt-2 flex items-center gap-1.5 text-xs text-med">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            The end of the suspicious window is earlier than its start.
          </p>
        )}

        {/* Footer: provenance + save */}
        <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-line pt-4">
          <span className="text-xs text-fg-muted">
            Created by <span className="font-medium text-fg-muted">{incident.createdBy || 'unknown'}</span> on{' '}
            {formatDateTime(Date.parse(incident.createdAt))}
          </span>
          <Button icon={Save} onClick={handleSave}>
            Save
          </Button>
        </div>
      </Card>

      {/* ---- 2. Recap StatCards ---- */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 2xl:grid-cols-6">
        <StatCard icon={Activity} label="Browser events" value={recap.events} />
        <StatCard icon={Terminal} label="Commands" value={recap.commands} />
        <StatCard icon={HardDrive} label="Endpoint artifacts" value={recap.artifacts} />
        <StatCard icon={Flag} label="Flagged" value={flaggedCount} tone={flaggedCount > 0 ? 'accent' : 'default'} />
        <StatCard icon={Bookmark} label="Bookmarks" value={recap.bookmarks} />
        <StatCard icon={StickyNote} label="Notes" value={notesCount} />
      </div>

      {/* ---- 3. Incident timeline ---- */}
      <Card title="Incident timeline" icon={ListTree}>
        <IncidentTimeline incident={incident} />
      </Card>
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* Small labelled field wrapper for the details form.                         */
/* -------------------------------------------------------------------------- */

function Field({ id, label, icon: Icon, children }) {
  return (
    <div>
      <label htmlFor={id} className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-fg-muted">
        {Icon && <Icon className="h-3.5 w-3.5" aria-hidden="true" />}
        {label}
      </label>
      {children}
    </div>
  )
}
