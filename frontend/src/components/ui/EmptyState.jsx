import AsciiSkull from './AsciiSkull.jsx'

/*
 * ============================================================================
 * EMPTY STATE — how Nik says "nothing here"
 * ============================================================================
 *
 * The rule every screen follows:
 *
 *  1. A page, a tab or the main list of a page with nothing in it shows the
 *     sleeping skull (`skull`), a title and a sentence that says how something
 *     gets here, with the button that makes one when the person may:
 *     "No playbook yet" / "Create one: it starts as a draft…".
 *  2. The same list emptied by a search or a filter shows the skull too, with
 *     other words: "No playbook matches" / what to change. A table that keeps
 *     its header says it in its body instead, in one line (DataTable's
 *     `emptyMessage`: "No events match the current filters").
 *  3. A screen that waits for a choice (no artifact selected, no kind of
 *     evidence chosen) is the first case: the skull, and what to choose.
 *  4. A small list inside something else (a widget, a section of a dialog, a
 *     menu, a side list) says it in one quiet line, without the skull:
 *     "Nothing here yet.", "No field matches.".
 *  5. What could not be read shows the skull with crossed eyes
 *     (`skull="error"`), "Unable to…" and the reason. What is loading is not
 *     an empty state: the skull that looks around, or the (o.o) wait
 *     (components/ui/Wait.jsx).
 *
 * `compact` is for a narrow place that is still the main list of what it
 * shows (a side panel, a dialog): the small skull and less room around it.
 *
 * @param {{
 *   skull?: boolean | 'error',     // the sleeping skull; 'error': crossed eyes
 *   compact?: boolean,
 *   icon?: Function,               // a lucide icon instead (not for an empty list: see the rule)
 *   illustration?: React.ReactNode, // anything else drawn above the title
 *   title: string,
 *   message?: React.ReactNode,
 *   action?: React.ReactNode,
 *   className?: string,
 * }} props
 */
export default function EmptyState({
  skull = false,
  compact = false,
  icon: Icon = null,
  illustration = null,
  title,
  message,
  action = null,
  className = '',
}) {
  const drawn =
    illustration ??
    (skull ? (
      <AsciiSkull preset={compact ? 'small' : 'medium'} eyes={skull === 'error' ? 'x' : 'closed'} tone="muted" />
    ) : null)
  return (
    <div
      className={[
        'flex flex-col items-center justify-center gap-3 text-center',
        'border border-dashed border-line bg-panel/40',
        compact ? 'px-4 py-6' : 'px-6 py-14',
        className,
      ].join(' ')}
    >
      {drawn}
      {!drawn && Icon && (
        <div className="flex h-14 w-14 items-center justify-center border border-line bg-panel">
          <Icon className="h-7 w-7 text-fg-muted" aria-hidden="true" />
        </div>
      )}
      <h3 className={`font-mono font-semibold text-fg ${compact ? 'text-sm' : 'text-base'}`}>{title}</h3>
      {message && <p className={`max-w-md text-fg-muted ${compact ? 'text-xs' : 'text-sm'}`}>{message}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}
