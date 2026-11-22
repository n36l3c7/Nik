import { useRef } from 'react'
import { ArrowDown, ArrowUp, ArrowUpDown, Download, Mail, Trash2 } from 'lucide-react'
import { getOsById } from '../../config/os.js'
import { cellText, cleanSort, neighbour } from '../../domain/incidentList.js'
import { fitTags } from '../../domain/incidentTags.js'
import { numberedName } from '../../domain/incidentName.js'
import { formatRelative } from '../../lib/time.js'
import { Chip, MicroSkull, SelectBox, SeverityTag, StatusTag } from '../ui/index.js'
import ConnectorLogo from '../ui/ConnectorLogo.jsx'
import IncidentNumber from '../ui/IncidentNumber.jsx'

/*
 * The table of the incident list: a row for each incident, the columns the
 * person chose, a click on a heading to order by it.
 *
 * A click on a row shows it in the quick view; a double click, or Enter on a
 * row, opens the incident. The arrows go to the row above and below, and the
 * quick view follows when it is open. The right-click menu of a row is the
 * one the side panel had. A click on a tag of a row filters the list by it.
 *
 * The first column selects: a click on its checkbox ticks the row, with Shift
 * the range from the last one ticked; the checkbox of the heading ticks the
 * rows on screen. On a row, Space ticks it, Shift and an arrow tick the next
 * one too, Ctrl/⌘+A ticks the rows on screen and Escape unticks everything
 * (components/ui/useSelection.js).
 */

const EMPTY = <span className="text-fg-subtle">—</span>

/** Compact icon-button for what is done to a row without opening it. */
function RowAction({ icon: Icon, label, danger = false, busy = false, onClick }) {
  return (
    <button
      type="button"
      title={label}
      aria-label={label}
      aria-busy={busy || undefined}
      disabled={busy}
      onClick={onClick}
      className={[
        'p-1.5 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
        danger ? 'text-fg-muted hover:bg-high-soft hover:text-high' : 'text-fg-muted hover:bg-raised hover:text-fg',
      ].join(' ')}
    >
      {busy ? <MicroSkull className="text-[10px] leading-none" /> : <Icon className="h-3.5 w-3.5" />}
    </button>
  )
}

function Cell({ row, column, types, onTag }) {
  const text = cellText(row, column, { types })
  switch (column.key) {
    case 'labels': {
      // The tags the cell has room for; a click on one asks the list for it.
      const { shown, more } = fitTags(row.tags)
      if (shown.length === 0) return EMPTY
      return (
        <span className="flex items-center gap-1">
          {shown.map((tag) => (
            <Chip
              key={tag}
              onClick={() => onTag(tag)}
              label={`Filter by the tag ${tag}`}
              title={`Filter by the tag ${tag}`}
            >
              #{tag}
            </Chip>
          ))}
          {more > 0 && (
            <span className="font-mono text-xs text-fg-muted" title={row.tags.slice(shown.length).join(', ')}>
              +{more}
            </span>
          )}
        </span>
      )
    }
    case 'number':
      return row.number ? <IncidentNumber number={row.number} className="text-xs" /> : EMPTY
    case 'name': {
      const os = getOsById(row.os)
      const OsIcon = os?.icon
      return (
        <span
          className={`flex min-w-0 items-center gap-1.5 font-semibold ${row.status === 'closed' ? 'text-fg-muted' : 'text-fg'}`}
        >
          {OsIcon && <OsIcon className={`h-3.5 w-3.5 shrink-0 ${os.accent}`} aria-label={os.label} />}
          {row.hasMail && <Mail className="h-3.5 w-3.5 shrink-0 text-accent" aria-label="Holds e-mails" />}
          <ConnectorLogo source={row.source} />
          <span className="max-w-[32rem] truncate" title={row.name}>
            {row.name}
          </span>
        </span>
      )
    }
    case 'severity':
      return row.severity ? <SeverityTag severity={row.severity} /> : EMPTY
    case 'status':
      return <StatusTag status={row.status} showOpen />
    case 'owner':
      return text ? <span className="font-mono text-xs">@{text}</span> : <span className="text-fg-subtle">nobody</span>
    case 'created':
      return text ? <span className="font-mono text-xs text-fg-muted">{text}</span> : EMPTY
    case 'modified':
      return text ? (
        <span className="font-mono text-xs text-fg-muted" title={text}>
          {formatRelative(row.updatedAt)}
        </span>
      ) : (
        EMPTY
      )
    case 'os':
      return getOsById(row.os)?.label ?? EMPTY
    default:
      return text ? (
        <span className="block max-w-[20rem] truncate" title={text}>
          {text}
        </span>
      ) : (
        EMPTY
      )
  }
}

/**
 * @param {{
 *   rows: object[],                    // the incidents, in the order to draw them
 *   columns: object[],                 // the columns shown, in order
 *   types: object[],
 *   sort: { key: string, dir: 'asc' | 'desc' } | null,
 *   onSort: (column: object) => void,
 *   shownId: string | null,            // the row the quick view shows
 *   onShow: (id: string) => void,      // a click
 *   onOpen: (id: string) => void,      // a double click, Enter
 *   onMove: (id: string) => void,      // the arrows went to another row
 *   onMenu: (event: MouseEvent, row: object) => void,
 *   onTag: (tag: string) => void,      // a click on a tag of a row
 *   canWrite: boolean,
 *   exportingId: string | null,
 *   onExport: (row: object) => void,
 *   onDelete: (row: object) => void,
 *   picked: object,                    // the selection: what useSelection() returns
 * }} props
 */
export default function IncidentTable({
  rows,
  columns,
  types,
  sort,
  onSort,
  shownId,
  onShow,
  onOpen,
  onMove,
  onMenu,
  onTag,
  canWrite,
  exportingId,
  onExport,
  onDelete,
  picked,
}) {
  const body = useRef(null)
  const current = cleanSort(sort)

  const focusRow = (id) => body.current?.querySelector(`tr[data-row="${CSS.escape(id)}"]`)?.focus()
  const onRowKey = (event, row) => {
    if (event.target !== event.currentTarget) return
    // The keys of the selection first: Space, Shift and an arrow, Ctrl/⌘+A, Escape.
    const moved = picked.key(event, row.id)
    if (moved !== undefined) {
      if (moved) focusRow(moved)
      return
    }
    if (event.key === 'Enter') {
      event.preventDefault()
      onOpen(row.id)
    } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault()
      const next = neighbour(
        rows.map((item) => item.id),
        row.id,
        event.key === 'ArrowDown' ? 1 : -1,
      )
      if (next === null || next === row.id) return
      body.current?.querySelector(`tr[data-row="${CSS.escape(next)}"]`)?.focus()
      onMove(next)
    }
  }

  return (
    <table aria-label="Incidents" className="w-full min-w-max border-collapse text-left text-[13px]">
      <thead className="sticky top-0 z-10 bg-canvas">
        <tr>
          <th scope="col" className="w-px border-b border-line pl-3">
            <SelectBox label="Select the incidents on screen" state={picked.page} onPick={picked.pickPage} />
          </th>
          {columns.map((column) => {
            const sorted = current.key === column.key
            const name = column.name ?? column.label
            return (
              <th
                key={column.key}
                scope="col"
                aria-sort={sorted ? (current.dir === 'asc' ? 'ascending' : 'descending') : undefined}
                className="whitespace-nowrap border-b border-line px-3 py-2 font-mono text-[11px] font-normal uppercase tracking-wider text-fg-muted"
              >
                <button
                  type="button"
                  onClick={() => onSort(column)}
                  aria-label={`Sort by ${name}`}
                  title={`Order the list by ${name.toLowerCase()}`}
                  className="inline-flex items-center gap-1 uppercase tracking-wider transition-colors hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  <span>{column.label}</span>
                  {!sorted ? (
                    <ArrowUpDown className="h-3 w-3 opacity-40" aria-hidden="true" />
                  ) : current.dir === 'asc' ? (
                    <ArrowUp className="h-3 w-3 text-accent" aria-hidden="true" />
                  ) : (
                    <ArrowDown className="h-3 w-3 text-accent" aria-hidden="true" />
                  )}
                </button>
              </th>
            )
          })}
          <th scope="col" className="w-px border-b border-line px-3 py-2">
            <span className="sr-only">Actions</span>
          </th>
        </tr>
      </thead>
      <tbody ref={body}>
        {rows.map((row) => {
          const shown = row.id === shownId
          const ticked = picked.has(row.id)
          return (
            <tr
              key={row.id}
              data-row={row.id}
              tabIndex={0}
              aria-current={shown ? 'true' : undefined}
              aria-selected={ticked}
              aria-label={numberedName(row)}
              onClick={(event) => !event.target.closest('button, a') && onShow(row.id)}
              onDoubleClick={(event) => !event.target.closest('button, a') && onOpen(row.id)}
              onKeyDown={(event) => onRowKey(event, row)}
              onContextMenu={(event) => onMenu(event, row)}
              className={[
                'group cursor-pointer border-b border-line-soft transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent',
                shown
                  ? 'bg-raised shadow-[inset_2px_0_0_var(--color-accent)]'
                  : ticked
                    ? 'bg-accent-soft/40'
                    : 'hover:bg-panel',
              ].join(' ')}
            >
              <td className="py-0 pl-3 align-middle">
                <SelectBox
                  label={`Select ${numberedName(row)}`}
                  checked={ticked}
                  onPick={(event) => picked.pick(row.id, event)}
                />
              </td>
              {columns.map((column) => (
                <td key={column.key} className="whitespace-nowrap px-3 py-2 align-middle text-fg">
                  <Cell row={row} column={column} types={types} onTag={onTag} />
                </td>
              ))}
              <td className="px-2 py-1 align-middle">
                {/* What is done to a row without opening it: seen on hover and with the keyboard. */}
                <span className="flex justify-end gap-0.5 opacity-0 transition-opacity group-focus-within:opacity-100 group-hover:opacity-100">
                  <RowAction
                    icon={Download}
                    label={`Export incident "${row.name}"`}
                    busy={exportingId === row.id}
                    onClick={() => onExport(row)}
                  />
                  {canWrite && (
                    <RowAction
                      icon={Trash2}
                      label={`Delete incident "${row.name}"`}
                      danger
                      onClick={() => onDelete(row)}
                    />
                  )}
                </span>
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}
