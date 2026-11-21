import { useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { Button, Modal } from '../ui/index.js'
import OsPicker from '../layout/OsPicker.jsx'
import { useIncidents, deriveIncidentName } from '../../context/IncidentContext.jsx'
import { normalizeOs } from '../../config/os.js'
import { SEVERITIES, STATUSES } from '../../domain/incidentName.js'
import { formatDateTime, localInputToMs, msToLocalInput } from '../../lib/time.js'
import { useUnsavedChanges } from '../../lib/unsaved.js'

/*
 * ============================================================================
 * EDIT THE INCIDENT — what it is called, how grave, whose, on which machine
 * ============================================================================
 *
 * The form that was the first card of the Summary until 5.3: the ticket, the
 * short title, the severity, the status, who it is assigned to, the host and
 * the user, the operating system of the host (which may be left out) and the
 * window of the suspicious activity. The Summary is a page the type arranges
 * now; this is where an incident itself is changed.
 *
 * Closing goes through its own form (a reason, what the type wants filled):
 * choosing "closed" here opens it after the rest is saved.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-2 text-sm text-fg placeholder:text-fg-muted ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

function Field({ id, label, children, wide = false }) {
  return (
    <div className={wide ? 'sm:col-span-2' : undefined}>
      <label htmlFor={id} className="mb-1.5 block font-mono text-xs text-fg-muted">
        {label}
      </label>
      {children}
    </div>
  )
}

/**
 * @param {{ incident: object, onClose: () => void }} props
 */
export default function EditIncidentDialog({ incident, onClose }) {
  const { updateIncidentMeta, assignees, askClose } = useIncidents()
  const [ticketId, setTicketId] = useState(incident.ticketId ?? '')
  const [title, setTitle] = useState(incident.title ?? '')
  const [severity, setSeverity] = useState(incident.severity ?? '')
  const [status, setStatus] = useState(incident.status ?? 'open')
  const [assignee, setAssignee] = useState(incident.assignee ?? '')
  const [host, setHost] = useState(incident.host ?? '')
  const [username, setUsername] = useState(incident.username ?? '')
  const [os, setOs] = useState(normalizeOs(incident.os))
  const [start, setStart] = useState(msToLocalInput(incident.suspiciousStart))
  const [end, setEnd] = useState(msToLocalInput(incident.suspiciousEnd))

  const now = JSON.stringify([ticketId, title, severity, status, assignee, host, username, os, start, end])
  const [opened] = useState(now)
  const unsaved = useUnsavedChanges(now !== opened, {
    what: 'The incident',
    name: incident.name,
    save: async () => save(),
  })

  const startMs = localInputToMs(start)
  const endMs = localInputToMs(end)
  // Said, not refused: a window written backwards is still saved.
  const inverted = startMs !== null && endMs !== null && endMs < startMs

  const save = (event) => {
    event?.preventDefault()
    const closing = status === 'closed' && (incident.status ?? 'open') !== 'closed'
    updateIncidentMeta(incident.id, {
      ticketId,
      title,
      severity: severity || null,
      status: closing ? (incident.status ?? 'open') : status,
      assignee,
      host,
      username,
      os,
      suspiciousStart: startMs,
      suspiciousEnd: endMs,
    })
    onClose()
    if (closing) askClose(incident.id)
  }

  return (
    <Modal
      open
      onClose={() => unsaved.leave(onClose)}
      title="Edit the incident"
      maxWidth="max-w-2xl"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="form-edit-incident">
            Save
          </Button>
        </>
      }
    >
      <form id="form-edit-incident" onSubmit={save} className="grid gap-4 sm:grid-cols-2">
        <Field id="incident-ticket" label="Ticket ID">
          <input
            id="incident-ticket"
            type="text"
            value={ticketId}
            onChange={(event) => setTicketId(event.target.value)}
            placeholder="e.g. INC-2041"
            className={INPUT}
          />
        </Field>
        <Field id="incident-severity" label="Severity">
          <select
            id="incident-severity"
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
            className={INPUT}
          >
            <option value="">—</option>
            {SEVERITIES.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>
        </Field>
        <Field id="incident-status" label="Status">
          <select
            id="incident-status"
            value={status}
            onChange={(event) => setStatus(event.target.value)}
            className={INPUT}
          >
            {STATUSES.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>
        </Field>
        <Field id="incident-assignee" label="Assigned to">
          <select
            id="incident-assignee"
            value={assignee}
            onChange={(event) => setAssignee(event.target.value)}
            className={INPUT}
          >
            <option value="">nobody</option>
            {[...new Set([...assignees, assignee].filter(Boolean))].map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </Field>
        <Field id="incident-title" label="Short title · replaces host and user in the name" wide>
          <input
            id="incident-title"
            type="text"
            value={title}
            onChange={(event) => setTitle(event.target.value)}
            placeholder="e.g. Invoice phishing, finance"
            className={INPUT}
          />
        </Field>
        <Field id="incident-host" label="Host">
          <input
            id="incident-host"
            type="text"
            value={host}
            onChange={(event) => setHost(event.target.value)}
            placeholder="e.g. WKS-042"
            className={INPUT}
          />
        </Field>
        <Field id="incident-username" label="User">
          <input
            id="incident-username"
            type="text"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            placeholder="e.g. j.doe"
            className={INPUT}
          />
        </Field>
        <div className="sm:col-span-2">
          <span className="mb-1.5 block font-mono text-xs text-fg-muted">
            Host operating system <span className="text-fg-subtle">· optional</span>
          </span>
          <OsPicker value={os} onChange={setOs} idPrefix="summary-os" />
        </div>
        <Field id="incident-start" label="Suspicious activity · start">
          <input
            id="incident-start"
            type="datetime-local"
            value={start}
            onChange={(event) => setStart(event.target.value)}
            className={`${INPUT} [color-scheme:light]`}
          />
        </Field>
        <Field id="incident-end" label="Suspicious activity · end">
          <input
            id="incident-end"
            type="datetime-local"
            value={end}
            onChange={(event) => setEnd(event.target.value)}
            className={`${INPUT} [color-scheme:light]`}
          />
        </Field>
        <div className="space-y-1.5 sm:col-span-2">
          <p className="text-xs text-fg-muted">
            Name: <span className="font-medium text-fg">{deriveIncidentName({ ticketId, title, host, username })}</span>
          </p>
          {inverted && (
            <p className="flex items-center gap-1.5 text-xs text-med">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              The end of the suspicious window is earlier than its start.
            </p>
          )}
          <p className="text-xs text-fg-muted">
            Created by {incident.createdBy || 'unknown'} on {formatDateTime(Date.parse(incident.createdAt))}
          </p>
        </div>
      </form>
    </Modal>
  )
}
