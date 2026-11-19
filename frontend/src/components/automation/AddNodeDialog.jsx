import { useMemo, useState } from 'react'
import { groupsOf } from '../../domain/automation/catalog.js'
import { Button, Modal } from '../ui/index.js'
import { INPUT } from './fields.jsx'

/*
 * "Add a node here…", from the right-click menu of the canvas: the library of
 * the side panel as a search. The node that is chosen lands where the click
 * was. Enter takes the first one that matches.
 */

/**
 * The dialog lives only while it is open, so that every opening starts from an empty search.
 *
 * @param {{
 *   open: boolean,
 *   entries: object[],                 // the library (the catalog's nodes)
 *   onAdd: (entry: object) => void,
 *   onClose: () => void,
 * }} props
 */
export default function AddNodeDialog(props) {
  return props.open ? <OpenDialog {...props} /> : null
}

function OpenDialog({ entries, onAdd, onClose }) {
  const [query, setQuery] = useState('')
  // What the side panel offers: nothing of a connector without an instance that is on.
  const groups = useMemo(
    () =>
      groupsOf(
        (entries ?? []).filter((entry) => entry.available !== false),
        query,
      ),
    [entries, query],
  )
  const first = groups[0]?.entries[0] ?? null
  const add = (entry) => {
    onAdd(entry)
    onClose()
  }
  return (
    <Modal
      open
      onClose={onClose}
      title="Add a node"
      footer={
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
      }
    >
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault()
          if (first) add(first)
        }}
      >
        <input
          type="search"
          value={query}
          autoFocus
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search nodes…"
          aria-label="Search the nodes to add"
          autoComplete="off"
          className={INPUT}
        />
        <div className="max-h-80 min-h-40 overflow-y-auto border border-line-soft">
          {groups.length === 0 && (
            <p role="status" className="px-3 py-2 text-xs text-fg-muted">
              No node matches “{query.trim()}”.
            </p>
          )}
          {groups.map((group) => (
            <div key={group.name} role="group" aria-label={group.name}>
              <p className="px-3 pb-0.5 pt-2 font-mono text-[11px] font-semibold text-fg-muted">{group.name}</p>
              {group.entries.map((entry) => (
                <button
                  key={entry.id}
                  type="button"
                  title={entry.description || undefined}
                  onClick={() => add(entry)}
                  className={[
                    'flex w-full items-baseline justify-between gap-3 px-3 py-1 text-left text-xs text-fg',
                    'hover:bg-raised focus-visible:bg-raised focus-visible:outline-none',
                    entry === first && query.trim() ? 'bg-accent-soft/50' : '',
                  ].join(' ')}
                >
                  <span className="min-w-0 break-words font-mono">{entry.name}</span>
                  <span className="min-w-0 truncate text-[11px] text-fg-muted">{entry.description}</span>
                </button>
              ))}
            </div>
          ))}
        </div>
        <p className="text-xs text-fg-muted">The node lands where you clicked. Enter adds the first one listed.</p>
      </form>
    </Modal>
  )
}
