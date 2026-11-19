import { useState } from 'react'
import { Plus } from 'lucide-react'

/*
 * The playbooks, and the branches of each, at the top of the editor's side
 * panel (5.2).
 *
 * A playbook is a row that opens into `main` (what runs, with its draft) and
 * its branches: a branch is a copy somebody works on beside it, pushed over
 * main when it is ready. The playbook that is open starts opened; a click on
 * any row goes there.
 *
 * Everybody who edits playbooks sees every branch. A branch is changed by who
 * made it (or an admin): the canvas of somebody else's is read-only, and
 * "New branch" makes one's own from it.
 */

const ROW =
  'flex w-full items-baseline gap-1.5 py-0.5 pr-1 text-left text-xs hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent'

/**
 * @param {{
 *   playbooks: object[],                 // every playbook, each with its `branches`
 *   current: object,                     // the playbook that is open (its detail)
 *   branchId: string | null,             // the branch on the canvas; null for main
 *   onOpen: (playbookId: string, branchId?: string | null) => void,
 *   onNew?: () => void,                  // make a branch of what is on the canvas
 * }} props
 */
export default function BranchTree({ playbooks, current, branchId, onOpen, onNew }) {
  const [opened, setOpened] = useState(() => new Set([current.id]))
  const rows = playbooks.some((item) => item.id === current.id) ? playbooks : [current, ...playbooks]
  const toggle = (id) =>
    setOpened((before) => {
      const next = new Set(before)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  return (
    <nav aria-label="Playbooks and their branches" className="shrink-0 border-b border-line-soft">
      <div className="flex items-center justify-between gap-2 px-2 pt-2">
        <span className="font-mono text-[10px] tracking-[0.12em] text-fg-muted">PLAYBOOKS</span>
        {onNew && (
          <button
            type="button"
            onClick={onNew}
            title="A copy of what is on the canvas, to work on beside main"
            className="flex items-center gap-1 font-mono text-[11px] text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <Plus size={11} aria-hidden="true" />
            New branch
          </button>
        )}
      </div>
      <ul className="max-h-44 overflow-y-auto px-2 py-1.5">
        {rows.map((playbook) => {
          const here = playbook.id === current.id
          const open = opened.has(playbook.id)
          // What the editor just read is newer than the list.
          const branches = (here ? current.branches : playbook.branches) ?? []
          const version = here ? current.version : playbook.version
          return (
            <li key={playbook.id}>
              <button
                type="button"
                aria-expanded={open}
                onClick={() => toggle(playbook.id)}
                className={`${ROW} ${here ? 'font-semibold text-fg' : 'text-fg-muted'}`}
              >
                <span aria-hidden="true" className="w-2.5 shrink-0 font-mono text-fg-subtle">
                  {open ? '▾' : '▸'}
                </span>
                <span className="min-w-0 flex-1 truncate">{playbook.name}</span>
                <span className="shrink-0 font-mono text-[10px] font-normal text-fg-muted">
                  {version ? `v${version}` : 'draft'}
                </span>
              </button>
              {open && (
                <ul className="pl-4">
                  <li>
                    <button
                      type="button"
                      aria-current={here && !branchId ? 'page' : undefined}
                      onClick={() => onOpen(playbook.id, null)}
                      className={`${ROW} ${here && !branchId ? 'text-fg' : 'text-fg-muted'}`}
                    >
                      <span className="min-w-0 flex-1 truncate">main</span>
                      <span className="shrink-0 font-mono text-[10px] text-fg-muted">
                        {version ? 'in use' : 'draft'}
                      </span>
                    </button>
                  </li>
                  {branches.map((branch) => {
                    const on = here && branch.id === branchId
                    return (
                      <li key={branch.id}>
                        <button
                          type="button"
                          aria-current={on ? 'page' : undefined}
                          title={
                            branch.behind
                              ? `${branch.name}: the playbook has a newer version than the one this branch started from`
                              : branch.name
                          }
                          onClick={() => onOpen(playbook.id, branch.id)}
                          className={`${ROW} ${on ? 'text-med-fg' : 'text-fg-muted'}`}
                        >
                          <span className="min-w-0 flex-1 truncate">{branch.name}</span>
                          <span className="shrink-0 font-mono text-[10px] text-fg-muted">
                            {branch.createdBy}
                            {branch.behind ? ' · behind' : ''}
                          </span>
                        </button>
                      </li>
                    )
                  })}
                </ul>
              )}
            </li>
          )
        })}
      </ul>
    </nav>
  )
}
