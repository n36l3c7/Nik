import OsPicker from '../layout/OsPicker.jsx'
import { SeverityTag } from '../ui/index.js'
import { DEFAULT_OS } from '../../config/os.js'
import { SEVERITIES, deriveIncidentName, hasIdentity } from '../../domain/incidentName.js'

/*
 * The identity fields of a new incident (ticket ID, short title, severity,
 * host, user, OS) with a live preview of the name they make. Used by the
 * "New incident" dialog and by the dialog of a dropped file.
 */

export const EMPTY_INCIDENT_FIELDS = { ticketId: '', title: '', severity: '', host: '', username: '', os: DEFAULT_OS }

const INPUT =
  'w-full border border-line bg-canvas px-3 py-2 font-mono text-sm text-fg placeholder:text-fg-muted ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

function Field({ id, label, hint, children }) {
  return (
    <div>
      <label htmlFor={id} className="mb-1.5 block font-mono text-xs text-fg-muted">
        {label} {hint && <span className="text-fg-subtle">· {hint}</span>}
      </label>
      {children}
    </div>
  )
}

/** True when the fields name the incident (at least one identity field). */
export const canCreateIncident = (fields) => hasIdentity(fields)

export default function IncidentFields({ value, onChange, idPrefix = 'new', autoFocus = true }) {
  const set = (key) => (event) => onChange({ ...value, [key]: event.target.value })
  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field id={`${idPrefix}-ticket`} label="Ticket ID">
          <input
            id={`${idPrefix}-ticket`}
            type="text"
            value={value.ticketId}
            onChange={set('ticketId')}
            placeholder="e.g. INC-2041"
            autoFocus={autoFocus}
            className={INPUT}
          />
        </Field>
        <Field id={`${idPrefix}-severity`} label="Severity" hint="a tag, not in the name">
          <select id={`${idPrefix}-severity`} value={value.severity} onChange={set('severity')} className={INPUT}>
            <option value="">—</option>
            {SEVERITIES.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </select>
        </Field>
      </div>
      <Field id={`${idPrefix}-title`} label="Short title" hint="replaces host and user in the name">
        <input
          id={`${idPrefix}-title`}
          type="text"
          value={value.title}
          onChange={set('title')}
          placeholder="e.g. Invoice phishing, finance"
          className={INPUT}
        />
      </Field>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field id={`${idPrefix}-host`} label="Host">
          <input
            id={`${idPrefix}-host`}
            type="text"
            value={value.host}
            onChange={set('host')}
            placeholder="e.g. WKS-FINANCE-01"
            className={INPUT}
          />
        </Field>
        <Field id={`${idPrefix}-username`} label="User">
          <input
            id={`${idPrefix}-username`}
            type="text"
            value={value.username}
            onChange={set('username')}
            placeholder="e.g. m.rossi"
            className={INPUT}
          />
        </Field>
      </div>
      <div>
        <span className="mb-1.5 block font-mono text-xs text-fg-muted">Host operating system</span>
        <OsPicker value={value.os} onChange={(os) => onChange({ ...value, os })} idPrefix={`${idPrefix}-os`} />
        <p className="mt-1.5 text-xs text-fg-muted">Drives the suggested artifact paths and the available shells.</p>
      </div>
      <div className="flex flex-wrap items-center gap-2 border border-line bg-canvas px-3 py-2">
        <span className="font-mono text-[11px] text-fg-muted">name</span>
        <span className="min-w-0 break-all font-mono text-sm text-fg" data-testid="incident-name-preview">
          {hasIdentity(value) ? deriveIncidentName(value) : '—'}
        </span>
        <SeverityTag severity={value.severity} />
      </div>
    </div>
  )
}
