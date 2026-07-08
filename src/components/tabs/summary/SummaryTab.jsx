import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Bookmark,
  CalendarClock,
  FileText,
  Flag,
  HardDrive,
  ListTree,
  MonitorCog,
  Save,
  Server,
  StickyNote,
  Terminal,
  User,
} from 'lucide-react'
import { Button, Card, StatCard } from '../../ui/index.js'
import IncidentTimeline from './IncidentTimeline.jsx'
import OsPicker from '../../layout/OsPicker.jsx'
import { useIncidents, deriveIncidentName } from '../../../context/IncidentContext.jsx'
import { BROWSERS } from '../../../config/browsers.js'
import { SHELLS } from '../../../config/shells.js'
import { ARTIFACT_CATEGORIES } from '../../../config/artifacts.js'
import { normalizeOs } from '../../../config/os.js'
import { formatDateTime } from '../../../utils/time.js'

/*
 * ============================================================================
 * SUMMARY TAB
 * ============================================================================
 *
 * The incident's home screen. It offers three things:
 *   1. Editable incident details (host, username, suspicious start/end) saved
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
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(
    d.getMinutes(),
  )}`
}

/** <input type="datetime-local"> value → Unix ms (local time), or null. */
function localInputToMs(value) {
  if (!value) return null
  const ms = new Date(value).getTime()
  return Number.isFinite(ms) ? ms : null
}

// Shared class strings for the editable form fields.
const INPUT_CLASS =
  'w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-800 ' +
  'placeholder:text-slate-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 ' +
  'dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:placeholder:text-slate-500'

// datetime-local additionally needs its native picker to follow the theme.
const DATETIME_CLASS = `${INPUT_CLASS} [color-scheme:light] dark:[color-scheme:dark]`

export default function SummaryTab({ incident }) {
  const { updateIncidentMeta } = useIncidents()

  /* ---- editable draft, reseeded whenever the active incident changes ---- */
  const [host, setHost] = useState(incident.host)
  const [username, setUsername] = useState(incident.username)
  const [os, setOs] = useState(normalizeOs(incident.os))
  const [start, setStart] = useState(msToLocalInput(incident.suspiciousStart))
  const [end, setEnd] = useState(msToLocalInput(incident.suspiciousEnd))

  useEffect(() => {
    // Only reset the draft on a genuine incident switch — not on every save
    // (which bumps updatedAt but keeps the same id), so typed edits survive.
    setHost(incident.host)
    setUsername(incident.username)
    setOs(normalizeOs(incident.os))
    setStart(msToLocalInput(incident.suspiciousStart))
    setEnd(msToLocalInput(incident.suspiciousEnd))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incident.id])

  const startMs = localInputToMs(start)
  const endMs = localInputToMs(end)
  // Warn (but do not block) when the suspicious window is inverted.
  const invertedRange = startMs !== null && endMs !== null && endMs < startMs

  const handleSave = () => {
    updateIncidentMeta(incident.id, {
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
      const bd = browsers[b.id]
      if (!bd) continue
      events += (bd.history?.length ?? 0) + (bd.downloads?.length ?? 0)
      bookmarks += bd.bookmarks?.length ?? 0
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
  const namePreview = deriveIncidentName(host, username)

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      {/* ---- 1. Incident details ---- */}
      <Card title="Incident details" icon={FileText}>
        <div className="grid gap-4 sm:grid-cols-2">
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
            <span className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-slate-500 dark:text-slate-400">
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
        <p className="mt-4 text-xs text-slate-500 dark:text-slate-400">
          Display name:{' '}
          <span className="font-medium text-slate-700 dark:text-slate-200">{namePreview}</span>
        </p>

        {/* Inverted-window warning */}
        {invertedRange && (
          <p className="mt-2 flex items-center gap-1.5 text-xs text-amber-600 dark:text-amber-400">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            The end of the suspicious window is earlier than its start.
          </p>
        )}

        {/* Footer: provenance + save */}
        <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 pt-4 dark:border-slate-800">
          <span className="text-xs text-slate-500 dark:text-slate-400">
            Created by{' '}
            <span className="font-medium text-slate-600 dark:text-slate-300">
              {incident.createdBy || 'unknown'}
            </span>{' '}
            on {formatDateTime(Date.parse(incident.createdAt))}
          </span>
          <Button icon={Save} onClick={handleSave}>
            Save
          </Button>
        </div>
      </Card>

      {/* ---- 2. Recap StatCards ---- */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
        <StatCard icon={Activity} label="Browser events" value={recap.events} />
        <StatCard icon={Terminal} label="Commands" value={recap.commands} />
        <StatCard icon={HardDrive} label="Endpoint artifacts" value={recap.artifacts} />
        <StatCard
          icon={Flag}
          label="Flagged"
          value={flaggedCount}
          tone={flaggedCount > 0 ? 'accent' : 'default'}
        />
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
      <label
        htmlFor={id}
        className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-slate-500 dark:text-slate-400"
      >
        {Icon && <Icon className="h-3.5 w-3.5" aria-hidden="true" />}
        {label}
      </label>
      {children}
    </div>
  )
}
