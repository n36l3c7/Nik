import { X } from 'lucide-react'
import { selectionText } from '../../domain/selection.js'

/**
 * The bar that appears over a list when rows are selected: how many, what
 * can be done to them, and Clear. The same on every list.
 *
 *   12 selected · Select all 1,284 that match · [ Actions… ▾ ] · Clear
 *
 * The actions are one menu, so the bar is the same in a wide table and in a
 * narrow panel, and wraps on a phone. An action a person may not do is not
 * given to the bar at all. With nothing selected the bar is not drawn, but
 * the sentence that says a change of the filter emptied the selection is.
 *
 * @param {{
 *   picked: object,                 // what useSelection() returns
 *   noun: string,                   // "incidents": what "all that match" are
 *   actions: ({ id: string, label: string, onSelect: () => void } | { group: string } | false | null)[],
 *   className?: string,
 * }} props
 */
export default function BulkBar({ picked, noun, actions, className = '' }) {
  if (picked.count === 0) {
    return picked.notice ? (
      <p role="status" className={`px-3 py-1.5 font-mono text-xs text-fg-muted ${className}`}>
        {picked.notice}
      </p>
    ) : null
  }
  // The menu, in groups: { group } starts one.
  const groups = []
  for (const action of actions.filter(Boolean)) {
    if (action.group !== undefined) groups.push({ label: action.group, items: [] })
    else {
      if (groups.length === 0) groups.push({ label: '', items: [] })
      groups[groups.length - 1].items.push(action)
    }
  }
  const offered = groups.flatMap((group) => group.items)
  return (
    <section
      aria-label="Selection"
      className={`flex flex-wrap items-center gap-x-3 gap-y-2 border border-accent bg-accent-soft px-3 py-2 text-sm ${className}`}
    >
      <p role="status" className="font-semibold text-fg">
        {selectionText(picked.selection, picked.total)}
      </p>
      {picked.offersAll && (
        <button
          type="button"
          onClick={picked.pickAll}
          className="text-left text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          Select all {picked.total.toLocaleString('en-US')} that match
        </button>
      )}
      {offered.length > 0 ? (
        <select
          aria-label={`Actions on the selected ${noun}`}
          value=""
          onChange={(event) => {
            const chosen = offered.find((action) => action.id === event.target.value)
            chosen?.onSelect()
          }}
          className="h-8 min-w-0 max-w-full cursor-pointer border border-line bg-canvas pl-2 pr-7 font-mono text-[13px] text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <option value="">Actions…</option>
          {groups.map((group, index) =>
            group.label ? (
              <optgroup key={group.label} label={group.label}>
                {group.items.map((action) => (
                  <option key={action.id} value={action.id}>
                    {action.label}
                  </option>
                ))}
              </optgroup>
            ) : (
              group.items.map((action) => (
                <option key={`${index}-${action.id}`} value={action.id}>
                  {action.label}
                </option>
              ))
            ),
          )}
        </select>
      ) : (
        <span className="font-mono text-xs text-fg-muted">Your roles let you read, not change</span>
      )}
      <button
        type="button"
        onClick={picked.reset}
        className="ml-auto inline-flex h-8 items-center gap-1 px-2 text-fg-muted hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        <X className="h-3.5 w-3.5" aria-hidden="true" />
        Clear
      </button>
    </section>
  )
}
