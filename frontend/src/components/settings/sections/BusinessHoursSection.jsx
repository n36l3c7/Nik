import { useEffect, useMemo, useState } from 'react'
import { Clock } from 'lucide-react'
import { useSettings } from '../../../context/SettingsContext.jsx'
import ListPicker from '../ListPicker.jsx'
import { matchZone, timeZones, zoneOf } from '../../../domain/timeZones.js'

/*
 * Business-hours settings section: the window beyond which events are marked
 * as a time anomaly. Extracted from the old SettingsModal into the sectioned
 * SettingsPanel.
 */

const HOUR_OPTIONS = Array.from({ length: 24 }, (_, h) => ({
  value: String(h),
  label: `${String(h).padStart(2, '0')}:00`,
}))

const inputBase =
  'border bg-panel px-2.5 py-1.5 text-sm text-fg ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ' +
  ''

function HourSelect({ value, onChange }) {
  return (
    <select
      value={String(value)}
      onChange={(e) => onChange(Number(e.target.value))}
      className={`${inputBase} border-line`}
    >
      {HOUR_OPTIONS.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  )
}

/** The time zone: typed or picked from the IANA names (the box suggests them); applied when it names one. */
function ZoneInput({ value, onChange }) {
  const zones = useMemo(() => timeZones(), [])
  const [text, setText] = useState(value)
  useEffect(() => setText(value), [value])
  const found = matchZone(text, zones)
  return (
    <label className="flex items-center gap-2 text-sm text-fg-muted">
      Time zone
      <input
        list="business-hours-zones"
        value={text}
        spellCheck={false}
        autoComplete="off"
        aria-invalid={text.trim() !== '' && !found ? true : undefined}
        onChange={(event) => {
          setText(event.target.value)
          const next = matchZone(event.target.value, zones)
          if (next && next !== value) onChange(next)
        }}
        onBlur={() => setText(found || value)}
        className={`${inputBase} w-64 border-line font-mono`}
      />
      <datalist id="business-hours-zones">
        {zones.map((name) => (
          <option key={name} value={name} />
        ))}
      </datalist>
    </label>
  )
}

export default function BusinessHoursSection() {
  const { businessHours, setBusinessHours } = useSettings()

  return (
    <section className="space-y-4">
      <div>
        <div className="flex items-center gap-2">
          <Clock className="h-5 w-5 text-accent" />
          <h2 className="text-base font-semibold text-fg">Business hours</h2>
        </div>
        <p className="mt-1 text-sm text-fg-muted">
          Working time, told in the time zone below. Sigma rules such as "RDP logon outside working hours" and the SLA
          timers that count business hours use it; events of mail, network and samples that fall{' '}
          <strong>outside</strong> it are highlighted on their tabs and on the timeline.
        </p>
      </div>

      <ListPicker
        setting="businessHours"
        label="Hours"
        hint="The form below edits the list that is chosen. SLA timers that count business hours read the same hours, in the time zone chosen there."
      />

      <div className="flex flex-wrap items-center gap-x-6 gap-y-3 border border-line bg-panel p-4">
        <label className="flex items-center gap-2 text-sm text-fg-muted">
          From
          <HourSelect value={businessHours.startHour} onChange={(startHour) => setBusinessHours({ startHour })} />
        </label>
        <label className="flex items-center gap-2 text-sm text-fg-muted">
          to
          <HourSelect value={businessHours.endHour} onChange={(endHour) => setBusinessHours({ endHour })} />
        </label>
        <ZoneInput value={zoneOf(businessHours)} onChange={(tz) => setBusinessHours({ tz })} />
        <label className="flex cursor-pointer items-center gap-2 text-sm text-fg-muted">
          <input
            type="checkbox"
            checked={!!businessHours.flagWeekends}
            onChange={(e) => setBusinessHours({ flagWeekends: e.target.checked })}
            className="h-4 w-4 border-line text-accent focus-visible:ring-2 focus-visible:ring-accent"
          />
          Also flag weekends
        </label>
      </div>
    </section>
  )
}
