/**
 * StatCard — compact statistic card (KPI) with icon, label, prominent
 * monospace value and an optional hint.
 *
 * Tones: 'default' (neutral), 'accent' (info blue), 'danger' (HIGH red),
 * 'warn' (MED amber), 'ok' (green).
 */
const TONES = {
  default: { icon: 'text-fg-muted', value: 'text-fg' },
  accent: { icon: 'text-info', value: 'text-info' },
  danger: { icon: 'text-high', value: 'text-high' },
  warn: { icon: 'text-med', value: 'text-med' },
  ok: { icon: 'text-accent', value: 'text-accent' },
}

export default function StatCard({ icon: Icon = null, label, value, tone = 'default', hint }) {
  const toneClasses = TONES[tone] ?? TONES.default

  return (
    <div className="flex items-center gap-3 border border-line bg-panel px-4 py-3">
      {Icon && (
        <div className="flex h-10 w-10 shrink-0 items-center justify-center border border-line bg-canvas">
          <Icon className={`h-5 w-5 ${toneClasses.icon}`} aria-hidden="true" />
        </div>
      )}
      <div className="min-w-0">
        <div className="truncate text-xs text-fg-muted">{label}</div>
        <div className={`font-mono text-2xl font-extrabold tabular-nums leading-tight ${toneClasses.value}`}>
          {value}
        </div>
        {hint && <div className="truncate text-xs text-fg-muted">{hint}</div>}
      </div>
    </div>
  )
}
