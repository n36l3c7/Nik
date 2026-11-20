import { useMemo, useState } from 'react'
import { LIBRARY_TABS, libraryOf } from '../../domain/automation/catalog.js'
import { DRAG_TYPE } from './Canvas.jsx'
import { INPUT } from './fields.jsx'
import ResizeHandle, { useResizablePane } from '../ui/ResizeHandle.jsx'

/*
 * The library: the blocks a playbook is made of, in three tabs. Commands are
 * what Nik and the connectors do, one group for each, closed until opened;
 * only the connectors with an instance that is on are there. Scripts and the
 * nodes of the flow have a tab of their own. The search looks in all three.
 *
 * An entry is dragged onto the canvas, or added with a click or Enter: it
 * lands under the selected node.
 */

const EDGES = {
  Flow: 'border-l-med-line',
  Nik: 'border-l-accent',
  Files: 'border-l-accent',
  Scripts: 'border-l-violet-line',
}

/**
 * @param {{
 *   entries: object[],
 *   onAdd: (entry: object) => void,
 *   disabled?: boolean,
 *   header?: import('react').ReactNode,   // what stands above the tabs: the playbooks and their branches
 * }} props
 */
export default function NodeLibrary({ entries, onAdd, disabled = false, header = null }) {
  const [query, setQuery] = useState('')
  const [tab, setTab] = useState('commands')
  // The groups somebody opened: closed at first, each remembered while the editor is open.
  const [opened, setOpened] = useState(() => new Set())
  const pane = useResizablePane('automation.library', { initial: 220, min: 180, max: 420 })
  const { groups, counts, searching, hidden } = useMemo(() => libraryOf(entries, tab, query), [entries, tab, query])
  // One group alone (the flow, the scripts) has nothing to hide behind.
  const isOpen = (name) => searching || groups.length === 1 || opened.has(name)
  const toggle = (name, open) =>
    setOpened((current) => {
      const next = new Set(current)
      if (open) next.add(name)
      else next.delete(name)
      return next
    })
  return (
    <>
      <aside
        aria-label="Node library"
        style={pane.style}
        className="flex min-h-0 w-full shrink-0 flex-col border-r border-line bg-panel md:w-[var(--pane-w)]"
      >
        {header}
        <div role="tablist" aria-label="Kinds of blocks" className="flex border-b border-line-soft">
          {LIBRARY_TABS.map((item) => (
            <button
              key={item.id}
              type="button"
              role="tab"
              aria-selected={!searching && tab === item.id}
              onClick={() => {
                setTab(item.id)
                setQuery('')
              }}
              className={[
                '-mb-px flex-1 border-b-2 px-1 py-2 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent',
                !searching && tab === item.id
                  ? 'border-accent text-fg'
                  : 'border-transparent text-fg-muted hover:text-fg',
              ].join(' ')}
            >
              {item.label} <span className="font-mono text-[10px] text-fg-subtle">{counts[item.id]}</span>
            </button>
          ))}
        </div>
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
            <details
              key={group.name}
              open={isOpen(group.name)}
              onToggle={(event) => {
                // While it is searched, or alone, a group is open whatever was chosen.
                if (!searching && groups.length > 1) toggle(group.name, event.currentTarget.open)
              }}
              className="border border-line-soft"
            >
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
                      {entry.premium && (
                        <span className="shrink-0 text-violet" title="The vendor gives this command to a paid plan">
                          premium
                        </span>
                      )}
                    </button>
                  </li>
                ))}
              </ul>
            </details>
          ))}
          {!searching && tab === 'commands' && hidden > 0 && (
            <p className="px-1 pt-1 text-[11px] leading-snug text-fg-muted">
              {hidden} {hidden === 1 ? 'connector has' : 'connectors have'} no instance that is on: their commands are
              offered once one is, in Settings, Connectors.
            </p>
          )}
        </div>
      </aside>
      <ResizeHandle {...pane.handle} label="Resize the node library" className="hidden md:block" />
    </>
  )
}
