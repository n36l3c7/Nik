import { useEffect, useMemo, useState } from 'react'
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
} from 'lucide-react'
import SearchInput from './SearchInput.jsx'
import Select from './Select.jsx'
import Button from './Button.jsx'

/**
 * Generic comparison used by sorting:
 * - null/empty values always last (in ascending order);
 * - numbers compared numerically;
 * - strings with English localeCompare (case-insensitive, numeric-aware).
 */
function compareValues(a, b) {
  const aEmpty = a === null || a === undefined || a === ''
  const bEmpty = b === null || b === undefined || b === ''
  if (aEmpty && bEmpty) return 0
  if (aEmpty) return 1
  if (bEmpty) return -1
  if (typeof a === 'number' && typeof b === 'number') return a - b
  return String(a).localeCompare(String(b), 'en', { sensitivity: 'base', numeric: true })
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
}) {
  const [query, setQuery] = useState('')
  const [sort, setSort] = useState(defaultSort) // { key, dir:'asc'|'desc' } | null
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(defaultPageSize)

  // Reset to the first page when the search or the incoming data change
  useEffect(() => {
    setPage(1)
  }, [query, data])

  // 1) Filter: case-insensitive search on the given keys
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q || searchKeys.length === 0) return data
    return data.filter((row) =>
      searchKeys.some((key) => String(row[key] ?? '').toLowerCase().includes(q)),
    )
  }, [data, query, searchKeys])

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
      <ArrowUp className="h-3.5 w-3.5 text-cyan-600 dark:text-cyan-400" aria-hidden="true" />
    ) : (
      <ArrowDown className="h-3.5 w-3.5 text-cyan-600 dark:text-cyan-400" aria-hidden="true" />
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

      {/* Container with horizontal scroll for wide tables */}
      <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
        <table className="w-full min-w-max text-left text-sm">
          <thead className="bg-slate-50 dark:bg-slate-900/60">
            <tr className="border-b border-slate-200 dark:border-slate-800">
              {columns.map((column) => (
                <th
                  key={column.key}
                  scope="col"
                  className={[
                    'whitespace-nowrap px-4 py-3 text-xs font-semibold uppercase tracking-wider',
                    'text-slate-500 dark:text-slate-400',
                    column.align === 'right' ? 'text-right' : 'text-left',
                    column.headerClassName ?? '',
                  ].join(' ')}
                >
                  {column.sortable ? (
                    <button
                      type="button"
                      onClick={() => handleSort(column)}
                      aria-label={`Sort by ${column.label}`}
                      className="inline-flex items-center gap-1 rounded uppercase tracking-wider transition-colors hover:text-slate-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 dark:hover:text-slate-200"
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
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800/70">
            {paged.length === 0 ? (
              // No rows: message centered across the full width
              <tr>
                <td
                  colSpan={columns.length || 1}
                  className="px-4 py-12 text-center text-sm text-slate-500 dark:text-slate-400"
                >
                  {emptyMessage}
                </td>
              </tr>
            ) : (
              paged.map((row, index) => (
                <tr
                  key={rowKey(row, index)}
                  className={`transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/40 ${rowClassName(row)}`}
                >
                  {columns.map((column) => (
                    <td
                      key={column.key}
                      className={[
                        'px-4 py-2.5 align-middle',
                        column.align === 'right' ? 'text-right' : '',
                        column.className ?? '',
                      ].join(' ')}
                    >
                      {column.render ? column.render(row) : row[column.key] ?? '—'}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Footer: page-size selector, results range, navigation */}
      <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-slate-500 dark:text-slate-400">
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
          <span className="tabular-nums">
            {total === 0 ? 'No results' : `${from}–${to} of ${total} results`}
          </span>
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
