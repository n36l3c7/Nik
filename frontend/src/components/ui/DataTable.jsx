import { useDeferredValue, useEffect, useMemo, useState } from 'react'
import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from 'lucide-react'
import BulkBar from './BulkBar.jsx'
import SearchInput from './SearchInput.jsx'
import Select from './Select.jsx'
import SelectBox from './SelectBox.jsx'
import Button from './Button.jsx'
import { useSelection } from './useSelection.js'

// One collator for every comparison: localeCompare with options rebuilds it
// on each call, which is ten times slower on tables with hundreds of
// thousands of rows.
const collator = new Intl.Collator('en', { sensitivity: 'base', numeric: true })

/**
 * Generic comparison used by sorting:
 * - null/empty values always last (in ascending order);
 * - numbers compared numerically;
 * - strings with an English collator (case-insensitive, numeric-aware).
 */
function compareValues(a, b) {
  const aEmpty = a === null || a === undefined || a === ''
  const bEmpty = b === null || b === undefined || b === ''
  if (aEmpty && bEmpty) return 0
  if (aEmpty) return 1
  if (bEmpty) return -1
  if (typeof a === 'number' && typeof b === 'number') return a - b
  return collator.compare(String(a), String(b))
}

/**
 * DataTable — reusable advanced table: integrated search, per-column
 * sorting, full pagination, toolbar slot and per-row styling.
 *
 * Column contract:
 * `{ key, label, sortable=false, render?:(row)=>node, sortAccessor?:(row)=>any,
 *    className?, headerClassName?, align?='left'|'right' }`
 *
 * Data pipeline (all memoized): filter (search) → sort → paginate.
 * `onRowContextMenu(event, row)` opens the app's right-click menu on a row (see
 * ContextMenuContext); `initialQuery` pre-fills the search box.
 * `onRowClick(row)` makes rows open (click or Enter); clicks on buttons
 * and links inside a row keep their own behaviour.
 *
 * `selectable` gives the table a first column of checkboxes and the bar of the
 * bulk actions over it (components/ui/useSelection.js, BulkBar.jsx):
 * `{ id: (row) => string, label: (row) => string, noun, filter?,
 *    actions: (rows, picked) => action[] }`. `actions` is given the rows that
 * are selected (every row the search keeps, when "all that match" is); the
 * selection is emptied when the search or `filter` changes.
 */
export default function DataTable({
  columns = [],
  data = [],
  searchKeys = [],
  searchPlaceholder = 'Search…',
  defaultPageSize = 25,
  pageSizeOptions = [10, 25, 50, 100],
  defaultSort = null,
  rowClassName = () => '',
  toolbar = null,
  emptyMessage = 'No data available',
  rowKey = (row, i) => row.id ?? i,
  onRowClick = null,
  onRowContextMenu = null,
  initialQuery = '',
  selectable = null,
}) {
  const [query, setQuery] = useState(initialQuery)
  // The input updates at once; filtering and sorting follow when React is
  // idle, so typing stays responsive on large tables.
  const deferredQuery = useDeferredValue(query)
  const [sort, setSort] = useState(defaultSort) // { key, dir:'asc'|'desc' } | null
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(defaultPageSize)

  // Reset to the first page when the search or the incoming data change
  useEffect(() => {
    setPage(1)
  }, [deferredQuery, data])

  // 1) Filter: case-insensitive search on the given keys
  const filtered = useMemo(() => {
    const q = deferredQuery.trim().toLowerCase()
    if (!q || searchKeys.length === 0) return data
    return data.filter((row) =>
      searchKeys.some((key) =>
        String(row[key] ?? '')
          .toLowerCase()
          .includes(q),
      ),
    )
  }, [data, deferredQuery, searchKeys])

  // 2) Sort: use the column's sortAccessor if defined, otherwise row[key]
  const sorted = useMemo(() => {
    if (!sort) return filtered
    const column = columns.find((c) => c.key === sort.key)
    const accessor = column?.sortAccessor ?? ((row) => row[sort.key])
    const direction = sort.dir === 'desc' ? -1 : 1
    return [...filtered].sort((a, b) => direction * compareValues(accessor(a), accessor(b)))
  }, [filtered, sort, columns])

  // 3) Pagination ("safe" page in case the results shrink)
  const total = sorted.length
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const safePage = Math.min(page, totalPages)

  const paged = useMemo(() => {
    const start = (safePage - 1) * pageSize
    return sorted.slice(start, start + pageSize)
  }, [sorted, safePage, pageSize])

  // The selection: inside what the search keeps, across its pages and whatever the order.
  const idOf = selectable?.id
  const pageIds = useMemo(() => (idOf ? paged.map(idOf) : []), [paged, idOf])
  const picked = useSelection({
    filter: `${deferredQuery.trim().toLowerCase()}\n${selectable?.filter ?? ''}`,
    pageIds,
    total,
  })
  const selectedRows = () => (picked.all ? sorted : sorted.filter((row) => picked.has(idOf(row))))
  const columnCount = columns.length + (selectable ? 1 : 0)

  // Displayed range: "X–Y of Z results"
  const from = total === 0 ? 0 : (safePage - 1) * pageSize + 1
  const to = Math.min(safePage * pageSize, total)

  /** Header click: cycle asc → desc on the same column, asc on a new one */
  const handleSort = (column) => {
    if (!column.sortable) return
    setSort((previous) =>
      previous && previous.key === column.key
        ? { key: column.key, dir: previous.dir === 'asc' ? 'desc' : 'asc' }
        : { key: column.key, dir: 'asc' },
    )
    setPage(1)
  }

  /** Sort-state icon for a sortable column */
  const renderSortIcon = (column) => {
    if (!sort || sort.key !== column.key) {
      return <ArrowUpDown className="h-3.5 w-3.5 opacity-50" aria-hidden="true" />
    }
    return sort.dir === 'asc' ? (
      <ArrowUp className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
    ) : (
      <ArrowDown className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
    )
  }

  const hasSearch = searchKeys.length > 0

  return (
    <div className="space-y-3">
      {/* Top bar: integrated search + parent toolbar slot */}
      {(hasSearch || toolbar) && (
        <div className="flex flex-wrap items-center gap-3">
          {hasSearch && (
            <SearchInput
              value={query}
              onChange={setQuery}
              placeholder={searchPlaceholder}
              className="w-full sm:max-w-xs"
            />
          )}
          {toolbar}
        </div>
      )}

      {selectable && (
        <BulkBar
          picked={picked}
          noun={selectable.noun}
          actions={picked.count > 0 ? selectable.actions(selectedRows(), picked) : []}
        />
      )}

      {/* Container with horizontal scroll for wide tables */}
      <div className="overflow-x-auto border border-line bg-panel">
        <table className="w-full min-w-max text-left text-[13px]">
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
              {columns.map((column) => (
                <th
                  key={column.key}
                  scope="col"
                  className={[
                    'whitespace-nowrap px-4 py-2.5 font-mono text-xs font-normal lowercase',
                    'text-fg-muted',
                    column.align === 'right' ? 'text-right' : 'text-left',
                    column.headerClassName ?? '',
                  ].join(' ')}
                >
                  {column.sortable ? (
                    <button
                      type="button"
                      onClick={() => handleSort(column)}
                      aria-label={`Sort by ${column.label}`}
                      className="inline-flex items-center gap-1 lowercase transition-colors hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    >
                      <span>{column.label}</span>
                      {renderSortIcon(column)}
                    </button>
                  ) : (
                    column.label
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-line-soft">
            {paged.length === 0 ? (
              // No rows: message centered across the full width
              <tr>
                <td colSpan={columnCount || 1} className="px-4 py-12 text-center font-mono text-sm text-fg-muted">
                  {emptyMessage}
                </td>
              </tr>
            ) : (
              paged.map((row, index) => (
                <tr
                  key={rowKey(row, index)}
                  data-row={selectable ? idOf(row) : undefined}
                  aria-selected={selectable ? picked.has(idOf(row)) : undefined}
                  className={`transition-colors hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent ${onRowClick ? 'cursor-pointer' : ''} ${rowClassName(row)} ${selectable && picked.has(idOf(row)) ? 'outline outline-1 -outline-offset-1 outline-accent/60' : ''}`}
                  onClick={
                    onRowClick ? (event) => !event.target.closest('button, a, input') && onRowClick(row) : undefined
                  }
                  onKeyDown={
                    onRowClick || selectable
                      ? (event) => {
                          if (event.target !== event.currentTarget) return
                          // The keys of the selection first: Space, Shift and an arrow, Ctrl/⌘+A, Escape.
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
                  onContextMenu={onRowContextMenu ? (event) => onRowContextMenu(event, row) : undefined}
                  // A row that can be opened, selected or has a menu is a Tab stop: the keyboard reaches what the mouse does.
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
                  {columns.map((column) => (
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

      {/* Footer: page-size selector, results range, navigation */}
      <div className="flex flex-wrap items-center justify-between gap-3 font-mono text-xs text-fg-muted">
        <div className="flex flex-wrap items-center gap-3">
          <Select
            label="Rows per page"
            value={String(pageSize)}
            onChange={(value) => {
              setPageSize(Number(value))
              setPage(1)
            }}
            options={pageSizeOptions.map((n) => ({ value: String(n), label: String(n) }))}
          />
          <span className="tabular-nums">{total === 0 ? 'No results' : `${from}–${to} of ${total} results`}</span>
        </div>

        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="xs"
            icon={ChevronsLeft}
            aria-label="First page"
            disabled={safePage <= 1}
            onClick={() => setPage(1)}
          />
          <Button
            variant="ghost"
            size="xs"
            icon={ChevronLeft}
            aria-label="Previous page"
            disabled={safePage <= 1}
            onClick={() => setPage(safePage - 1)}
          />
          <span className="px-2 tabular-nums">
            Page {safePage} of {totalPages}
          </span>
          <Button
            variant="ghost"
            size="xs"
            icon={ChevronRight}
            aria-label="Next page"
            disabled={safePage >= totalPages}
            onClick={() => setPage(safePage + 1)}
          />
          <Button
            variant="ghost"
            size="xs"
            icon={ChevronsRight}
            aria-label="Last page"
            disabled={safePage >= totalPages}
            onClick={() => setPage(totalPages)}
          />
        </div>
      </div>
    </div>
  )
}
