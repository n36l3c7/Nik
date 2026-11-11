import { statusLabel } from '../../domain/incidentName.js'

/*
 * Where the work on an incident stands: shown next to the name in the panel
 * and the header. An open incident shows no tag unless `showOpen` is set.
 */

const STYLES = {
  open: 'border-line text-fg-muted',
  in_progress: 'border-accent text-accent',
  closed: 'border-line bg-raised text-fg-muted',
}

export default function StatusTag({ status, showOpen = false, className = '' }) {
  if (!STYLES[status] || (status === 'open' && !showOpen)) return null
  return (
    <span
      title={`Status: ${statusLabel(status)}`}
      className={`inline-flex shrink-0 items-center whitespace-nowrap border px-1 font-mono text-[10px] leading-[15px] ${STYLES[status]} ${className}`}
    >
      {statusLabel(status)}
    </span>
  )
}
