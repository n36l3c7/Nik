import { CornerDownRight, Download, Link2, Search } from 'lucide-react'
import { EVENT_TYPE_META } from '../../../utils/events.js'

/*
 * Event-type icon + label (visit / search / redirect / download), used inside
 * the tables to tell at a glance what kind of row each entry is.
 */

const ICONS = {
  visit: Link2,
  search: Search,
  redirect: CornerDownRight,
  download: Download,
}

// Per-type icon colors, each with its dark counterpart.
const ICON_COLORS = {
  visit: 'text-slate-400 dark:text-slate-500',
  search: 'text-cyan-600 dark:text-cyan-400',
  redirect: 'text-amber-600 dark:text-amber-400',
  download: 'text-emerald-600 dark:text-emerald-400',
}

/**
 * @param {{ type: 'visit'|'search'|'redirect'|'download', withLabel?: boolean }} props
 */
export default function EventTypeIcon({ type, withLabel = false }) {
  const Icon = ICONS[type] ?? Link2
  const meta = EVENT_TYPE_META[type] ?? EVENT_TYPE_META.visit
  return (
    <span
      className="inline-flex items-center gap-1.5"
      title={meta.label}
      aria-label={meta.label}
    >
      <Icon className={`h-4 w-4 shrink-0 ${ICON_COLORS[type] ?? ICON_COLORS.visit}`} />
      {withLabel && (
        <span className="text-xs font-medium text-slate-600 dark:text-slate-300">
          {meta.label}
        </span>
      )}
    </span>
  )
}
