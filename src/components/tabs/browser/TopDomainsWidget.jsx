/*
 * "Top 5 visited domains" widget: ranking of the most frequent domains in the
 * browsing history, drawn with horizontal bars proportional to the visit count
 * (normalized against the most visited domain).
 */
import { useMemo } from 'react'
import { TrendingUp } from 'lucide-react'
import { Card } from '../../ui/index.js'
import { topDomains } from '../../../utils/url.js'

/**
 * @param {{ history?: Array }} props — raw history entries (one per visit)
 */
export default function TopDomainsWidget({ history = [] }) {
  // topDomains returns [{ domain, count }] already sorted descending.
  const domains = useMemo(() => topDomains(history, 5), [history])

  // The first element is the maximum: the base for the percentage widths.
  const maxCount = domains.length > 0 ? domains[0].count : 0

  return (
    <Card title="Top 5 visited domains" icon={TrendingUp}>
      {domains.length === 0 ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">
          No domains to show
        </p>
      ) : (
        <ul className="space-y-3">
          {domains.map(({ domain, count }) => (
            <li key={domain}>
              <div className="mb-1 flex items-baseline justify-between gap-3">
                <span className="truncate font-mono text-xs text-slate-700 dark:text-slate-300">
                  {domain}
                </span>
                <span className="shrink-0 text-xs font-medium text-slate-500 dark:text-slate-400">
                  {count} {count === 1 ? 'visit' : 'visits'}
                </span>
              </div>
              {/* Proportional bar (min 4% so it stays visible) */}
              <div className="h-2 w-full overflow-hidden rounded bg-slate-100 dark:bg-slate-800">
                <div
                  className="h-full rounded bg-cyan-500/70 transition-all duration-500"
                  style={{ width: `${Math.max((count / maxCount) * 100, 4)}%` }}
                />
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}
