import { ArrowDown, ArrowUp } from 'lucide-react'
import { nextSort } from '../../../domain/network.js'

/*
 * A column header that sorts its table: click for ascending, again for
 * descending, a third time for the original order.
 */
export default function SortHeader({ label, sortKey, sort, onSort, className = '', align = 'left' }) {
  const active = sort?.key === sortKey
  const Icon = active && sort.dir === 'desc' ? ArrowDown : ArrowUp
  return (
    <th
      aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}
      className={`${className} p-0 font-normal`}
    >
      <button
        type="button"
        onClick={() => onSort(nextSort(sort, sortKey))}
        title={`Sort by ${label}`}
        className={[
          'flex w-full items-center gap-1 px-1.5 py-1 hover:text-fg',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent',
          align === 'right' ? 'justify-end' : '',
          active ? 'text-fg' : '',
        ].join(' ')}
      >
        <span className="truncate">{label}</span>
        <Icon className={`h-3 w-3 shrink-0 ${active ? '' : 'opacity-0'}`} aria-hidden="true" />
      </button>
    </th>
  )
}
