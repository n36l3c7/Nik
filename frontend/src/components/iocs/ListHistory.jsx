import { useState } from 'react'
import { ChevronDown, ChevronRight, History } from 'lucide-react'
import { changeLine, historyLine, verdictCounts } from '../../domain/iocLibrary.js'
import { formatDateTime } from '../../lib/time.js'

/*
 * What the checks of a list found. One line says what the last check
 * changed ("since the last check: 4 became malicious, 1 cleared"); opened,
 * the indicators it changed and the last checks of the list, each with how
 * many indicators it had and how many of each verdict.
 */

/**
 * @param {{ history: { last: object | null, history: object[], changes: object[] } | null }} props
 */
export default function ListHistory({ history }) {
  const [open, setOpen] = useState(false)
  if (!history) return null
  const Chevron = open ? ChevronDown : ChevronRight
  return (
    <section aria-label="History of the list" className="border border-line">
      <button
        type="button"
        aria-expanded={open}
        disabled={!history.last}
        onClick={() => setOpen((old) => !old)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent disabled:cursor-default"
      >
        {history.last ? (
          <Chevron className="h-4 w-4 shrink-0 text-fg-muted" aria-hidden="true" />
        ) : (
          <History className="h-4 w-4 shrink-0 text-fg-muted" aria-hidden="true" />
        )}
        <span className="min-w-0 flex-1 text-fg">{historyLine(history.last)}</span>
        {history.history.length > 1 && (
          <span className="shrink-0 text-xs text-fg-muted">{history.history.length} checks kept</span>
        )}
      </button>
      {open && history.last && (
        <div className="grid gap-4 border-t border-line-soft bg-sunken px-3 py-3 lg:grid-cols-2">
          <div className="min-w-0">
            <h3 className="mb-1 text-xs font-medium text-fg-muted">What the last check changed</h3>
            {history.changes.length === 0 ? (
              <p className="text-xs text-fg-muted">Nothing: every indicator is as it was.</p>
            ) : (
              <ul className="max-h-56 space-y-0.5 overflow-y-auto font-mono text-xs">
                {history.changes.map((change) => (
                  <li key={`${change.type}|${change.value}`} className="flex gap-2">
                    <span className="min-w-0 flex-1 truncate text-fg" title={change.value}>
                      {change.value}
                    </span>
                    <span className="shrink-0 font-sans text-fg-muted">{changeLine(change)}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <div className="min-w-0 overflow-x-auto">
            <table className="w-full text-left text-xs">
              <caption className="mb-1 text-left text-xs font-medium text-fg-muted">The checks of this list</caption>
              <thead>
                <tr className="border-b border-line text-fg-muted">
                  <th scope="col" className="py-1 pr-2 font-medium">
                    Checked
                  </th>
                  <th scope="col" className="py-1 pr-2 text-right font-medium">
                    Indicators
                  </th>
                  <th scope="col" className="py-1 pr-2 text-right font-medium">
                    Changed
                  </th>
                  <th scope="col" className="py-1 font-medium">
                    Verdicts
                  </th>
                </tr>
              </thead>
              <tbody>
                {history.history.map((line) => (
                  <tr key={line.checkId} className="border-b border-line-soft last:border-0">
                    <td className="whitespace-nowrap py-1 pr-2 text-fg">
                      {formatDateTime(Date.parse(line.checkedAt))}
                    </td>
                    <td className="py-1 pr-2 text-right tabular-nums text-fg">{line.total}</td>
                    <td className="py-1 pr-2 text-right tabular-nums text-fg">{line.changed}</td>
                    <td className="py-1 text-fg-muted">{verdictCounts(line.byVerdict)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </section>
  )
}
