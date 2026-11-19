import { formatNumber } from '../../domain/incidentName.js'

/**
 * The number of an incident (`#00042`), written before its name wherever an
 * incident is named. Renders nothing for an incident that has no number yet.
 *
 * @param {{ number?: number | null, className?: string }} props
 */
export default function IncidentNumber({ number, className = '' }) {
  const text = formatNumber(number)
  if (!text) return null
  return <span className={`shrink-0 font-mono tabular-nums text-accent ${className}`}>{text}</span>
}
