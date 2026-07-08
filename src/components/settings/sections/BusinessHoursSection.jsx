import { Clock } from 'lucide-react'
import { useSettings } from '../../../context/SettingsContext.jsx'

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
  'rounded-lg border bg-white px-2.5 py-1.5 text-sm text-slate-800 ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 ' +
  'dark:bg-slate-950 dark:text-slate-100'

function HourSelect({ value, onChange }) {
  return (
    <select
      value={String(value)}
      onChange={(e) => onChange(Number(e.target.value))}
      className={`${inputBase} border-slate-200 dark:border-slate-700`}
    >
      {HOUR_OPTIONS.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  )
}

export default function BusinessHoursSection() {
  const { businessHours, setBusinessHours } = useSettings()

  return (
    <section className="space-y-4">
      <div>
        <div className="flex items-center gap-2">
          <Clock className="h-5 w-5 text-cyan-600 dark:text-cyan-400" />
          <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">
            Business hours
          </h2>
        </div>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Events (visits, downloads, commands and endpoint artifacts) that occur{' '}
          <strong>outside</strong> this window are highlighted as a time anomaly across every tab
          and on the timeline.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-x-6 gap-y-3 rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
        <label className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
          From
          <HourSelect
            value={businessHours.startHour}
            onChange={(startHour) => setBusinessHours({ startHour })}
          />
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
          to
          <HourSelect
            value={businessHours.endHour}
            onChange={(endHour) => setBusinessHours({ endHour })}
          />
        </label>
        <label className="flex cursor-pointer items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
          <input
            type="checkbox"
            checked={!!businessHours.flagWeekends}
            onChange={(e) => setBusinessHours({ flagWeekends: e.target.checked })}
            className="h-4 w-4 rounded border-slate-300 text-cyan-600 focus-visible:ring-2 focus-visible:ring-cyan-500 dark:border-slate-600 dark:bg-slate-800"
          />
          Also flag weekends
        </label>
      </div>
    </section>
  )
}
