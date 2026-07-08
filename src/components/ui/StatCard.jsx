/**
 * StatCard — compact statistic card (KPI) with icon, label,
 * prominent value and an optional hint.
 *
 * Tones: 'default' (neutral), 'accent' (cyan), 'danger' (red),
 * 'warn' (amber), 'ok' (green).
 */

// Classes per tone: icon box + value color (always light + dark)
const TONES = {
  default: {
    icon: 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400',
    value: 'text-slate-800 dark:text-slate-100',
  },
  accent: {
    icon: 'bg-cyan-50 text-cyan-600 dark:bg-cyan-500/10 dark:text-cyan-400',
    value: 'text-cyan-600 dark:text-cyan-400',
  },
  danger: {
    icon: 'bg-red-50 text-red-600 dark:bg-red-500/10 dark:text-red-400',
    value: 'text-red-600 dark:text-red-400',
  },
  warn: {
    icon: 'bg-amber-50 text-amber-600 dark:bg-amber-500/10 dark:text-amber-400',
    value: 'text-amber-600 dark:text-amber-400',
  },
  ok: {
    icon: 'bg-emerald-50 text-emerald-600 dark:bg-emerald-500/10 dark:text-emerald-400',
    value: 'text-emerald-600 dark:text-emerald-400',
  },
}

export default function StatCard({ icon: Icon = null, label, value, tone = 'default', hint }) {
  const toneClasses = TONES[tone] ?? TONES.default

  return (
    <div className="flex items-center gap-4 rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
      {Icon && (
        <div
          className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-lg ${toneClasses.icon}`}
        >
          <Icon className="h-5 w-5" aria-hidden="true" />
        </div>
      )}
      <div className="min-w-0">
        <div className="truncate text-xs font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
          {label}
        </div>
        <div className={`text-2xl font-semibold tabular-nums leading-tight ${toneClasses.value}`}>
          {value}
        </div>
        {hint && (
          <div className="truncate text-xs text-slate-500 dark:text-slate-400">{hint}</div>
        )}
      </div>
    </div>
  )
}
