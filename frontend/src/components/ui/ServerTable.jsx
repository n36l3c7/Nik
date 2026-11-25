import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ArrowDown,
  ArrowUp,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  Columns3,
  Filter,
  Layers,
  X,
  EyeOff,
  ArrowUpDown,
} from 'lucide-react'
import { useContextMenu } from '../../context/ContextMenuContext.jsx'
import {
  PAGE_SIZES,
  activeFilters,
  back,
  cellValue,
  cursorOf,
  directionOf,
  filterChips,
  forward,
  nextOrder,
  offsetOf,
  queryKey,
  rangeText,
  readSettings,
  visibleColumns,
  withFilter,
  withoutFilter,
} from '../../domain/serverTable.js'
import { useLayer } from '../../lib/layers.js'
import BulkBar from './BulkBar.jsx'
import Button from './Button.jsx'
import SearchInput from './SearchInput.jsx'
import Select from './Select.jsx'
import SelectBox from './SelectBox.jsx'
import { useSelection } from './useSelection.js'
import { Wait } from './Wait.jsx'

const SEARCH_DELAY_MS = 300
const NO_PAGES = []

/** The settings of a table in this browser (hidden columns, page size); nothing when storage is refused. */
function readStored(tableKey, columns) {
  let raw = null
  if (tableKey) {
    try {
      raw = localStorage.getItem(`nik.table.${tableKey}`)
    } catch {
      raw = null
    }
  }
  return readSettings(raw, columns)
}

function writeStored(tableKey, settings) {
  if (!tableKey) return
  try {
    localStorage.setItem(`nik.table.${tableKey}`, JSON.stringify(settings))
  } catch {
    // Storage refused (private mode, quota): the choice lasts for this page only.
  }
}

/** A small menu that opens under its button, closes on Escape and on a press outside it. */
function Popover({ open, onClose, children, align = 'left', label }) {
  const ref = useRef(null)
  useLayer(ref, { open, onClose, trap: false })
  useEffect(() => {
    if (!open) return undefined
    const away = (event) => {
      if (!ref.current?.contains(event.target)) onClose()
    }
    document.addEventListener('mousedown', away)
    return () => document.removeEventListener('mousedown', away)
  }, [open, onClose])
  if (!open) return null
  return (
    <div
      ref={ref}
      role="menu"
      aria-label={label}
      className={`absolute top-full z-30 mt-1 min-w-48 max-w-72 border border-line bg-raised py-1 text-[13px] normal-case shadow-2xl ${align === 'right' ? 'right-0' : 'left-0'}`}
    >
      {children}
    </div>
  )
}

function MenuItem({ icon: Icon, children, onSelect, disabled = false, title }) {
  return (
    <button
      type="button"
      role="menuitem"
      disabled={disabled}
      title={title}
      onClick={onSelect}
      className="flex w-full items-center gap-2 px-3 py-1.5 text-left font-sans text-fg hover:bg-panel focus-visible:bg-panel focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
    >
      {Icon && <Icon className="h-3.5 w-3.5 shrink-0 text-fg-muted" aria-hidden="true" />}
      <span className="min-w-0 flex-1 truncate">{children}</span>
    </button>
  )
}

/**
 * ServerTable: a table whose rows come from the server, a page at a time (the lists of host evidence
 * hold millions of records, so nothing here ever holds more than a page).
 *
 * `load({ cursor, limit, order, filters, signal }) => Promise<{ items, next, total?, capped? }>`: `next`
 * is the cursor of the following page (null at the end); `total` comes with the first page only and is
 * kept for the others; `capped` says the server stopped counting ("100,000+"). `load` is read when a
 * request is made: a new function does not reload, a change of `refreshKey` reloads the current page in
 * place (rows stay on screen, dimmed). Anything else that changes (filters, order, page size) aborts
 * the request in flight and asks for page one.
 *
 * Columns are DataTable's (`key, label, render, className, headerClassName, align`) plus:
 * `order` (the server order the column sorts by; `-order` is its reverse unless `reverse: false`),
 * `filterKey` (the filter a value of the column can be set on), `stackField` (the field `onStack`
 * is called with), `hideable` (the Columns menu can hide it), `value(row)` (what the cell holds, when it
 * is not `row[key]`). A column with any of these has a menu in its header: Sort, Filter on a value
 * (the value of the row the pointer was last on, also in the row's right-click menu), Stack values, Hide.
 *
 * `filters` and `onFiltersChange` are controlled; `filters.q` is the search box (sent after a pause) and
 * the other filters in force are chips that can be removed. `filterChips` and `toolbar` are slots of the
 * top bar. `tableKey` remembers the hidden columns and the page size in this browser.
 *
 * `selectable`: `{ id, label, noun, actions }` as in DataTable, but `actions(rows, picked, scope)` gets the
 * selected rows of the page on screen and `scope = { all, ids, filters, total }`: when "all that match" is
 * ticked, `all` is true and `filters` holds the filters (not rows) for the server to apply. "All that
 * match" is not offered when the server capped the count.
 *
 * `onRowClick(row)`, `onRowContextMenu(event, row, filterItems)` (the items are the menu entries that set
 * a filter: put them in the menu you open; without this prop the table opens a menu of them),
 * `rowClassName(row)`, `emptyMessage`, `defaultOrder`, `onStack(field)`. `hideChips`: names of filters that
 * have a control of their own in the toolbar and so are not repeated as chips. `chipLabel(name, value)`
 * writes the value of a chip (a column's own `chipLabel(value)` does it for its filter); `from` and `to` are
 * shown as a date and time.
 */
export default function ServerTable({
  load,
  columns,
  filters = {},
  onFiltersChange,
  filterChips: chipsSlot = null,
  chipLabel = null,
  toolbar = null,
  tableKey = '',
  selectable = null,
  onRowClick = null,
  onRowContextMenu = null,
  rowClassName = () => '',
  emptyMessage = 'No records',
  refreshKey = 0,
  onStack = null,
  defaultOrder = 'time',
  searchPlaceholder = 'Search…',
  rowKey = null,
  hideChips = NO_PAGES,
}) {
  const { openMenu } = useContextMenu()
  const [settings, setSettings] = useState(() => readStored(tableKey, columns))
  const [order, setOrder] = useState(defaultOrder)
  const [menu, setMenu] = useState(null) // the key of the column whose menu is open, or 'columns'
  const [attempt, setAttempt] = useState(0) // bumped by "Try again"
  const pageSize = settings.pageSize

  const changeSettings = (changes) => {
    const next = { ...settings, ...changes }
    setSettings(next)
    writeStored(tableKey, next)
  }

  // ---- The search box: typed at once, sent to the filters after a pause ----
  const [text, setText] = useState(filters.q ?? '')
  const sentRef = useRef(filters.q ?? '')
  const filtersRef = useRef(filters)
  filtersRef.current = filters
  useEffect(() => {
    // The filter changed from outside (a chip, a saved view): the box follows.
    if ((filters.q ?? '') !== sentRef.current) {
      sentRef.current = filters.q ?? ''
      setText(filters.q ?? '')
    }
  }, [filters.q])
  useEffect(() => {
    if (text === sentRef.current) return undefined
    const timer = setTimeout(() => {
      sentRef.current = text
      onFiltersChange?.(withFilter(filtersRef.current, 'q', text.trim()))
    }, SEARCH_DELAY_MS)
    return () => clearTimeout(timer)
  }, [text, onFiltersChange])

  // ---- The page: the cursors of the pages left, and what the server answered ----
  const key = queryKey(filters, order, pageSize)
  const [position, setPosition] = useState({ key, stack: NO_PAGES })
  // A new query is page one, whatever the stack was.
  const stack = position.key === key ? position.stack : NO_PAGES
  const cursor = cursorOf(stack)
  const [result, setResult] = useState({
    key: null,
    filterKey: '',
    rows: [],
    next: null,
    total: null,
    capped: false,
    loading: true,
    error: null,
  })

  const loadRef = useRef(load)
  loadRef.current = load
  useEffect(() => {
    const controller = new AbortController()
    const asked = activeFilters(filtersRef.current)
    setResult((held) => ({ ...held, loading: true, error: null }))
    Promise.resolve(loadRef.current({ cursor, limit: pageSize, order, filters: asked, signal: controller.signal }))
      .then((page) => {
        if (controller.signal.aborted) return
        setResult((held) => {
          const same = held.key === key
          const first = cursor === ''
          return {
            key,
            filterKey: JSON.stringify(asked),
            rows: page.items ?? [],
            next: page.next ?? null,
            // The count is made on the first page: the others keep it while the query is the same.
            total: first ? (page.total ?? null) : same ? (page.total ?? held.total) : null,
            capped: first ? Boolean(page.capped) : same ? Boolean(page.capped ?? held.capped) : false,
            loading: false,
            error: null,
          }
        })
      })
      .catch((error) => {
        if (controller.signal.aborted || error?.name === 'AbortError') return
        setResult((held) => ({ ...held, loading: false, error: error?.message || 'The list could not be loaded.' }))
      })
    return () => controller.abort()
  }, [key, cursor, order, pageSize, refreshKey, attempt])

  const goNext = () => setPosition({ key, stack: forward(stack, result.next) })
  const goBack = () => setPosition({ key, stack: back(stack) })
  const goFirst = () => setPosition({ key, stack: NO_PAGES })

  // ---- Columns ----
  const shown = useMemo(() => visibleColumns(columns, settings.hidden), [columns, settings.hidden])
  const hideable = columns.filter((column) => column.hideable)
  const toggleColumn = (columnKey) => {
    const hidden = settings.hidden.includes(columnKey)
      ? settings.hidden.filter((item) => item !== columnKey)
      : [...settings.hidden, columnKey]
    changeSettings({ hidden })
  }
  const hasMenu = (column) =>
    Boolean(column.order || column.filterKey || (column.stackField && onStack) || column.hideable)

  // ---- The row the pointer was last on: what "Filter on a value" filters by ----
  const lastRow = useRef(null)
  const setFilter = (name, value) => {
    onFiltersChange?.(withFilter(filters, name, value))
    setMenu(null)
  }
  const filterItems = (row) =>
    columns
      .filter((column) => column.filterKey && cellValue(column, row) !== null)
      .map((column) => {
        const value = cellValue(column, row)
        return {
          label: `Filter ${column.label} = ${String(value).slice(0, 60)}`,
          onSelect: () => onFiltersChange?.(withFilter(filters, column.filterKey, value)),
        }
      })
  const rowMenu = (event, row) => {
    const items = filterItems(row)
    if (onRowContextMenu) onRowContextMenu(event, row, items)
    else if (items.length > 0) openMenu(event, { title: 'Filter', items })
  }

  // ---- The selection ----
  const idOf = selectable?.id
  const rows = result.rows
  const pageIds = useMemo(() => (idOf ? rows.map(idOf) : []), [rows, idOf])
  const counted = result.capped ? 0 : (result.total ?? 0)
  const picked = useSelection({ filter: result.filterKey, pageIds, total: counted })
  const selectedRows = () => (picked.all ? rows : rows.filter((row) => picked.has(idOf(row))))
  const scope = () => ({
    all: picked.all,
    ids: picked.ids(),
    filters: picked.all ? JSON.parse(result.filterKey || '{}') : null,
    total: counted,
  })

  const chips = filterChips(filters, columns, chipLabel).filter((chip) => !hideChips.includes(chip.name))
  const columnCount = shown.length + (selectable ? 1 : 0)
  const busy = result.loading
  const offset = offsetOf(stack, pageSize)
  const sortHeader = (column) => {
    const direction = directionOf(order, column)
    if (direction === 'asc') return <ArrowUp className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
    if (direction === 'desc') return <ArrowDown className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
    return null
  }

  const closeMenu = useCallback(() => setMenu(null), [])

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <SearchInput value={text} onChange={setText} placeholder={searchPlaceholder} className="w-full sm:max-w-xs" />
        {chipsSlot}
        {toolbar}
        {hideable.length > 0 && (
          <div className="relative ml-auto">
            <Button
              variant="secondary"
              size="sm"
              icon={Columns3}
              aria-haspopup="menu"
              aria-expanded={menu === 'columns'}
              onClick={() => setMenu(menu === 'columns' ? null : 'columns')}
            >
              Columns
            </Button>
            <Popover open={menu === 'columns'} onClose={closeMenu} align="right" label="Columns">
              {hideable.map((column) => (
                <label
                  key={column.key}
                  className="flex cursor-pointer items-center gap-2 px-3 py-1.5 font-sans text-fg hover:bg-panel"
                >
                  <input
                    type="checkbox"
                    checked={!settings.hidden.includes(column.key)}
                    onChange={() => toggleColumn(column.key)}
                    className="accent-accent"
                  />
                  {column.label}
                </label>
              ))}
            </Popover>
          </div>
        )}
      </div>

      {chips.length > 0 && (
        <ul aria-label="Filters in force" className="flex flex-wrap items-center gap-2">
          {chips.map((chip) => (
            <li
              key={chip.name}
              className="inline-flex items-center gap-1 border border-accent-strong bg-accent-soft py-0.5 pl-2 pr-1 font-mono text-xs text-accent-fg"
            >
              <span className="max-w-64 truncate">{chip.text}</span>
              <button
                type="button"
                aria-label={`Remove the filter ${chip.text}`}
                onClick={() => onFiltersChange?.(chip.names.reduce(withoutFilter, filters))}
                className="p-0.5 hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <X className="h-3 w-3" aria-hidden="true" />
              </button>
            </li>
          ))}
        </ul>
      )}

      {selectable && (
        <BulkBar
          picked={picked}
          noun={selectable.noun}
          actions={picked.count > 0 ? selectable.actions(selectedRows(), picked, scope()) : []}
        />
      )}

      {result.error && (
        <div
          role="alert"
          className="flex flex-wrap items-center gap-3 border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg"
        >
          <span className="min-w-0 flex-1">{result.error}</span>
          <Button variant="secondary" size="xs" onClick={() => setAttempt((n) => n + 1)}>
            Try again
          </Button>
        </div>
      )}

      <div className="overflow-x-auto border border-line bg-panel">
        <table className="w-full min-w-max text-left text-[13px]" aria-busy={busy || undefined}>
          <thead className="bg-canvas">
            <tr className="border-b border-line">
              {selectable && (
                <th scope="col" className="w-px pl-2">
                  <SelectBox
                    label={`Select the ${selectable.noun} on this page`}
                    state={picked.page}
                    onPick={picked.pickPage}
                  />
                </th>
              )}
              {shown.map((column) => {
                const direction = directionOf(order, column)
                return (
                  <th
                    key={column.key}
                    scope="col"
                    aria-sort={direction === 'asc' ? 'ascending' : direction === 'desc' ? 'descending' : undefined}
                    className={[
                      'relative whitespace-nowrap px-4 py-2.5 font-mono text-xs font-normal lowercase text-fg-muted',
                      column.align === 'right' ? 'text-right' : 'text-left',
                      column.headerClassName ?? '',
                    ].join(' ')}
                  >
                    {hasMenu(column) ? (
                      <button
                        type="button"
                        aria-haspopup="menu"
                        aria-expanded={menu === column.key}
                        aria-label={`${column.label} menu`}
                        onClick={() => setMenu(menu === column.key ? null : column.key)}
                        className="inline-flex items-center gap-1 lowercase transition-colors hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                      >
                        <span>{column.label}</span>
                        {sortHeader(column)}
                        <ChevronDown className="h-3 w-3 opacity-60" aria-hidden="true" />
                      </button>
                    ) : (
                      column.label
                    )}
                    {hasMenu(column) && (
                      <Popover
                        open={menu === column.key}
                        onClose={closeMenu}
                        align={column.align === 'right' ? 'right' : 'left'}
                        label={`${column.label} menu`}
                      >
                        {column.order && (
                          <MenuItem
                            icon={ArrowUpDown}
                            onSelect={() => {
                              setOrder(nextOrder(order, column))
                              setMenu(null)
                            }}
                          >
                            {directionOf(order, column) === 'asc' && column.reverse !== false
                              ? 'Sort the other way'
                              : 'Sort'}
                          </MenuItem>
                        )}
                        {column.filterKey &&
                          (() => {
                            const value = lastRow.current ? cellValue(column, lastRow.current) : null
                            return (
                              <MenuItem
                                icon={Filter}
                                disabled={value === null}
                                title={value === null ? 'Point at a row with a value in this column first' : undefined}
                                onSelect={() => setFilter(column.filterKey, value)}
                              >
                                {value === null ? 'Filter on a value' : `Filter on ${String(value).slice(0, 40)}`}
                              </MenuItem>
                            )
                          })()}
                        {column.stackField && onStack && (
                          <MenuItem
                            icon={Layers}
                            onSelect={() => {
                              onStack(column.stackField)
                              setMenu(null)
                            }}
                          >
                            Stack values
                          </MenuItem>
                        )}
                        {column.hideable && (
                          <MenuItem
                            icon={EyeOff}
                            onSelect={() => {
                              toggleColumn(column.key)
                              setMenu(null)
                            }}
                          >
                            Hide
                          </MenuItem>
                        )}
                      </Popover>
                    )}
                  </th>
                )
              })}
            </tr>
          </thead>
          <tbody
            className={`divide-y divide-line-soft transition-opacity ${busy && rows.length > 0 ? 'opacity-50' : ''}`}
          >
            {rows.length === 0 ? (
              <tr>
                <td colSpan={columnCount || 1} className="px-4 py-12 text-center font-mono text-sm text-fg-muted">
                  {busy ? <Wait inline>Loading…</Wait> : result.error ? '' : emptyMessage}
                </td>
              </tr>
            ) : (
              rows.map((row, index) => (
                <tr
                  key={rowKey ? rowKey(row, index) : (idOf?.(row) ?? row.id ?? index)}
                  data-row={selectable ? idOf(row) : undefined}
                  aria-selected={selectable ? picked.has(idOf(row)) : undefined}
                  className={`transition-colors hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent ${onRowClick ? 'cursor-pointer' : ''} ${rowClassName(row)} ${selectable && picked.has(idOf(row)) ? 'outline outline-1 -outline-offset-1 outline-accent/60' : ''}`}
                  onPointerEnter={() => {
                    lastRow.current = row
                  }}
                  onFocus={() => {
                    lastRow.current = row
                  }}
                  onClick={
                    onRowClick ? (event) => !event.target.closest('button, a, input') && onRowClick(row) : undefined
                  }
                  onKeyDown={
                    onRowClick || selectable
                      ? (event) => {
                          if (event.target !== event.currentTarget) return
                          // The keys of the selection first: Space, Shift and an arrow, Ctrl/Cmd+A, Escape.
                          const moved = selectable ? picked.key(event, idOf(row)) : undefined
                          if (moved) {
                            event.currentTarget.parentElement
                              ?.querySelector(`tr[data-row="${CSS.escape(moved)}"]`)
                              ?.focus()
                          }
                          if (moved === undefined && event.key === 'Enter') onRowClick?.(row)
                        }
                      : undefined
                  }
                  onContextMenu={(event) => rowMenu(event, row)}
                  tabIndex={onRowClick || onRowContextMenu || selectable ? 0 : undefined}
                >
                  {selectable && (
                    <td className="py-0 pl-2 align-middle">
                      <SelectBox
                        label={`Select ${selectable.label(row)}`}
                        checked={picked.has(idOf(row))}
                        onPick={(event) => picked.pick(idOf(row), event)}
                      />
                    </td>
                  )}
                  {shown.map((column) => (
                    <td
                      key={column.key}
                      className={[
                        'px-4 py-2.5 align-middle',
                        column.align === 'right' ? 'text-right' : '',
                        column.className ?? '',
                      ].join(' ')}
                    >
                      {column.render ? column.render(row) : (row[column.key] ?? '—')}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 font-mono text-xs text-fg-muted">
        <div className="flex flex-wrap items-center gap-3">
          <Select
            label="Rows per page"
            value={String(pageSize)}
            onChange={(value) => changeSettings({ pageSize: Number(value) })}
            options={PAGE_SIZES.map((n) => ({ value: String(n), label: String(n) }))}
          />
          {busy && rows.length > 0 ? (
            <Wait inline className="text-xs">
              Loading…
            </Wait>
          ) : (
            <span role="status" className="tabular-nums">
              {rangeText({ offset, shown: rows.length, total: result.total, capped: result.capped })}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="xs"
            icon={ChevronsLeft}
            aria-label="First page"
            disabled={stack.length === 0}
            onClick={goFirst}
          />
          <Button
            variant="ghost"
            size="xs"
            icon={ChevronLeft}
            aria-label="Previous page"
            disabled={stack.length === 0}
            onClick={goBack}
          />
          <Button
            variant="ghost"
            size="xs"
            icon={ChevronRight}
            aria-label="Next page"
            disabled={!result.next || busy}
            onClick={goNext}
          />
        </div>
      </div>
    </div>
  )
}
