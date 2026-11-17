import { useMemo, useState } from 'react'
import { groupsOf } from '../../domain/automation/catalog.js'
import { DRAG_TYPE } from './Canvas.jsx'
import { INPUT } from './fields.jsx'

/*
 * The library: every node there is, in groups (Flow, Nik, HTTP, E-mail,
 * Scripts; one group per connector from 4.2). An entry is dragged onto the
 * canvas, or added with a click or Enter: it lands under the selected node.
 */

const EDGES = {
  Flow: 'border-l-med-line',
  Nik: 'border-l-accent',
  Scripts: 'border-l-violet-line',
}

/**
 * @param {{ entries: object[], onAdd: (entry: object) => void, disabled?: boolean }} props
 */
export default function NodeLibrary({ entries, onAdd, disabled = false }) {
  const [query, setQuery] = useState('')
  const groups = useMemo(() => groupsOf(entries, query), [entries, query])
  return (
    <aside
      aria-label="Node library"
      className="flex min-h-0 w-full shrink-0 flex-col border-r border-line bg-panel md:w-[220px]"
    >
      <div className="border-b border-line-soft p-2">
        <input
          type="search"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search nodes…"
          aria-label="Search nodes"
          autoComplete="off"
          className={INPUT}
        />
      </div>
      <div className="min-h-0 flex-1 space-y-1.5 overflow-y-auto p-2">
        {groups.length === 0 && (
          <p role="status" className="px-1 text-xs text-fg-muted">
            No node matches “{query.trim()}”.
          </p>
        )}
        {groups.map((group) => (
          <details key={group.name} open className="border border-line-soft">
            <summary className="flex cursor-pointer items-center justify-between gap-2 px-2 py-1 font-mono text-xs font-semibold text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent">
              {group.name}
              <span className="font-normal text-fg-subtle">{group.entries.length}</span>
            </summary>
            <ul className="space-y-1 px-1.5 pb-1.5">
              {group.entries.map((entry) => (
                <li key={entry.id}>
                  <button
                    type="button"
                    draggable={!disabled}
                    disabled={disabled}
                    title={entry.description || entry.name}
                    onDragStart={(event) => {
                      event.dataTransfer.setData(DRAG_TYPE, entry.id)
                      event.dataTransfer.effectAllowed = 'copy'
                    }}
                    onClick={() => onAdd(entry)}
                    className={[
                      'flex w-full cursor-grab items-baseline justify-between gap-2 border border-l-[3px] border-line bg-raised px-2 py-1 text-left font-mono text-[11px] text-fg',
                      'hover:border-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                      'disabled:cursor-not-allowed disabled:opacity-60',
                      EDGES[group.name] ?? 'border-l-info-line',
                    ].join(' ')}
                  >
                    <span className="min-w-0 break-words">{entry.name}</span>
                    {entry.changesOutside && (
                      <span
                        className="shrink-0 text-med"
                        title="Changes something outside Nik: asks approval by default"
                      >
                        changes
                      </span>
                    )}
                  </button>
                </li>
              ))}
            </ul>
          </details>
        ))}
      </div>
    </aside>
  )
}
