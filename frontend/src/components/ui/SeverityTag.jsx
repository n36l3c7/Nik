/*
 * The analysts' severity tag of an incident (low/medium/high/critical): shown
 * next to the name in the sidebar and the header, never part of the name.
 */

const STYLES = {
  low: 'border-line text-fg-muted',
  medium: 'border-med-line text-med-fg',
  high: 'border-high-line text-high',
  critical: 'border-high-line bg-high-soft text-high-fg',
}

export default function SeverityTag({ severity, className = '' }) {
  if (!STYLES[severity]) return null
  return (
    <span
      title={`Severity: ${severity}`}
      className={`inline-flex shrink-0 items-center border px-1 font-mono text-[10px] leading-[15px] ${STYLES[severity]} ${className}`}
    >
      {severity}
    </span>
  )
}
