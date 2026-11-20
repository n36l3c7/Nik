import { useEffect, useRef, useState } from 'react'
import { ChevronDown } from 'lucide-react'
import { groupFilters, menuLabel } from '../../domain/savedFilters.js'
import { useLayer } from '../../lib/layers.js'
import { useObjectMenu } from '../menu/useObjectMenu.js'
import { Badge } from '../ui/index.js'

/*
 * The button "Filter: <name>" of the incident list and the menu it opens:
 * one's own filters, those shared with everyone, the list with no filter,
 * and the dialog that manages them. Beside each filter, the mark of the one
 * the list opens with, or the button that makes it that one.
 */

const ITEM =
  'min-w-0 flex-1 truncate px-3 py-1.5 text-left text-[13px] text-fg hover:bg-accent-soft ' +
  'focus-visible:bg-accent-soft focus-visible:outline-none'
const SMALL =
  'mr-2 shrink-0 border border-line px-1.5 py-px text-[11px] text-fg-muted hover:bg-raised hover:text-fg ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const CAPTION = 'px-3 pb-1 pt-2 font-mono text-[11px] uppercase tracking-wider text-fg-muted'

function Menu({ filters, defaultId, chosenId, onChoose, onDefault, onManage, onClose }) {
  const ref = useRef(null)
  // Escape closes the menu and nothing under it; the focus returns to its button.
  useLayer(ref, { open: true, onClose, trap: false })
  const { mine, shared } = groupFilters(filters)
  const menu = useObjectMenu()

  // The arrows go from one line of the menu to the next, as in every menu of the app.
  const onKeyDown = (event) => {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return
    const items = [...ref.current.querySelectorAll('[role="menuitem"]')]
    const at = items.indexOf(document.activeElement)
    const next = items[(at + (event.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length]
    event.preventDefault()
    next?.focus()
  }

  const row = (filter, note = null) => (
    <li
      key={filter.id}
      role="none"
      className={`flex items-center ${filter.id === chosenId ? 'bg-raised' : ''}`}
      onContextMenu={(event) =>
        menu(event, {
          title: filter.name,
          actions: [
            { label: 'Show the list with this filter', onSelect: () => onChoose(filter) },
            filter.id !== defaultId && { label: 'Set as default', onSelect: () => onDefault(filter.id) },
            { label: 'Manage the filters…', onSelect: onManage },
          ],
          copy: [
            { label: 'Copy the name', text: filter.name },
            { label: 'Copy the query', text: filter.query },
          ],
        })
      }
    >
      <button
        type="button"
        role="menuitem"
        aria-current={filter.id === chosenId ? 'true' : undefined}
        onClick={() => onChoose(filter)}
        className={ITEM}
      >
        {filter.name}
        {note && <span className="ml-2 text-xs text-fg-muted">{note}</span>}
      </button>
      {filter.id === defaultId ? (
        <Badge color="emerald" className="mr-2 shrink-0">
          default
        </Badge>
      ) : (
        <button
          type="button"
          role="menuitem"
          aria-label={`Set ${filter.name} as default`}
          onClick={() => onDefault(filter.id)}
          className={SMALL}
        >
          Set as default
        </button>
      )}
    </li>
  )

  return (
    <div
      ref={ref}
      role="menu"
      tabIndex={-1}
      aria-label="Saved filters"
      onKeyDown={onKeyDown}
      className="absolute left-0 top-full z-40 mt-1 max-h-[70vh] w-[340px] max-w-[90vw] overflow-y-auto border border-line bg-panel py-1 shadow-2xl focus:outline-none"
    >
      <p className={CAPTION}>Mine</p>
      {mine.length === 0 ? (
        <p className="px-3 pb-1.5 text-xs text-fg-muted">
          None yet: write a query, then &ldquo;Save the filter…&rdquo;.
        </p>
      ) : (
        <ul role="none">{mine.map((filter) => row(filter, filter.shared ? 'shared' : null))}</ul>
      )}
      {shared.length > 0 && (
        <>
          <p className={`${CAPTION} mt-1 border-t border-line`}>Shared with everyone</p>
          <ul role="none">{shared.map((filter) => row(filter, `by ${filter.owner}`))}</ul>
        </>
      )}
      <div
        role="none"
        className={`mt-1 flex items-center border-t border-line ${chosenId === null ? 'bg-raised' : ''}`}
      >
        <button type="button" role="menuitem" onClick={() => onChoose(null)} className={`${ITEM} text-fg-muted`}>
          All incidents (no filter)
        </button>
        {defaultId === null ? (
          <Badge color="emerald" className="mr-2 shrink-0">
            default
          </Badge>
        ) : (
          <button
            type="button"
            role="menuitem"
            aria-label="Set no filter as default"
            onClick={() => onDefault(null)}
            className={SMALL}
          >
            Set as default
          </button>
        )}
      </div>
      <div role="none" className="flex border-t border-line">
        <button type="button" role="menuitem" onClick={onManage} className={`${ITEM} text-link`}>
          Manage the filters…<span className="ml-2 text-xs text-fg-muted">rename, share, delete</span>
        </button>
      </div>
    </div>
  )
}

/**
 * @param {{
 *   filters: object[], defaultId: string | null,
 *   chosen: object | null,                       // the filter that is chosen, or null for none
 *   onChoose: (filter: object | null) => void,
 *   onDefault: (id: string | null) => void,
 *   onManage: () => void,
 * }} props
 */
export default function FilterMenu({ filters, defaultId, chosen, onChoose, onDefault, onManage }) {
  const [open, setOpen] = useState(false)
  const box = useRef(null)
  const close = () => setOpen(false)
  // A click anywhere else closes the menu.
  useEffect(() => {
    if (!open) return undefined
    const onPointer = (event) => {
      if (!box.current?.contains(event.target)) setOpen(false)
    }
    window.addEventListener('pointerdown', onPointer, true)
    return () => window.removeEventListener('pointerdown', onPointer, true)
  }, [open])
  return (
    <div ref={box} className="relative shrink-0">
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((shown) => !shown)}
        title="The saved filters of this list"
        className={[
          'inline-flex h-8 max-w-[18rem] items-center gap-1.5 border px-3 text-sm transition-colors',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
          chosen ? 'border-accent text-accent-fg' : 'border-line text-fg hover:bg-raised',
        ].join(' ')}
      >
        <span className="truncate">{menuLabel(chosen)}</span>
        <ChevronDown className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      </button>
      {open && (
        <Menu
          filters={filters}
          defaultId={defaultId}
          chosenId={chosen?.id ?? null}
          onClose={close}
          onChoose={(filter) => {
            close()
            onChoose(filter)
          }}
          onDefault={onDefault}
          onManage={() => {
            close()
            onManage()
          }}
        />
      )}
    </div>
  )
}
