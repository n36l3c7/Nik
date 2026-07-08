/*
 * "Most frequent web searches" widget: extracts the queries typed on known
 * search engines (utils/url.js) and ranks them by frequency. Queries that match
 * the SOC detection rules are marked with a "suspicious" badge
 * (red = high severity, amber = medium).
 */
import { useMemo } from 'react'
import { Search } from 'lucide-react'
import { Badge, Card } from '../../ui/index.js'
import { topSearchQueries } from '../../../utils/url.js'

/**
 * @param {{ history?: Array, engine: object }} props
 *   `engine` is a SOC engine (from useSocEngine): used to mark queries as
 *   suspicious according to the current keyword rules.
 */
export default function SearchQueriesWidget({ history = [], engine }) {
  // Top 5 queries, enriched with any matching suspicious keyword rules.
  const queries = useMemo(
    () =>
      topSearchQueries(history, 5).map((item) => {
        // Analyze the query alone (as a title) to reuse the SOC engine.
        const matches = engine
          ? engine.matchKeywords({ url: '', title: item.query })
          : []
        const severity = matches.some((rule) => rule.severity === 'high')
          ? 'high'
          : matches.length > 0
            ? 'medium'
            : null
        return { ...item, matches, severity }
      }),
    [history, engine],
  )

  return (
    <Card title="Most frequent web searches" icon={Search}>
      {queries.length === 0 ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">
          No search queries found in URLs
        </p>
      ) : (
        <ol className="space-y-2.5">
          {queries.map(({ query, count, matches, severity }, index) => (
            <li key={query} className="flex items-center gap-2.5">
              {/* Ranking position */}
              <span className="w-5 shrink-0 text-right text-xs font-semibold text-slate-400 dark:text-slate-500">
                {index + 1}.
              </span>
              <span className="min-w-0 flex-1 truncate font-mono text-xs text-slate-700 dark:text-slate-300">
                &ldquo;{query}&rdquo;
              </span>
              {severity && (
                <Badge
                  color={severity === 'high' ? 'red' : 'amber'}
                  title={`Matches detection rules: ${matches
                    .map((rule) => rule.label)
                    .join(', ')}`}
                >
                  suspicious
                </Badge>
              )}
              {/* Query frequency */}
              <Badge color="slate" title={`Searched ${count} time(s)`}>
                ×{count}
              </Badge>
            </li>
          ))}
        </ol>
      )}
    </Card>
  )
}
