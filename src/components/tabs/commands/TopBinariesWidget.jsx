/*
 * "Top 5 executables" widget: ranking of the most frequently invoked binaries
 * in the command history, drawn with horizontal bars proportional to the count
 * (normalized against the most used one). Mirrors TopDomainsWidget.
 */
import { useMemo } from 'react'
import { TrendingUp } from 'lucide-react'
import { Card } from '../../ui/index.js'
import { topBinaries } from '../../../utils/commands.js'

/**
 * @param {{ commands?: Array }} props — raw command entries
 */
export default function TopBinariesWidget({ commands = [] }) {
  const binaries = useMemo(() => topBinaries(commands, 5), [commands])
  const maxCount = binaries.length > 0 ? binaries[0].count : 0

  return (
    <Card title="Top 5 executables" icon={TrendingUp}>
      {binaries.length === 0 ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">No commands to show</p>
      ) : (
        <ul className="space-y-3">
          {binaries.map(({ binary, count }) => (
            <li key={binary}>
              <div className="mb-1 flex items-baseline justify-between gap-3">
                <span className="truncate font-mono text-xs text-slate-700 dark:text-slate-300">
                  {binary}
                </span>
                <span className="shrink-0 text-xs font-medium text-slate-500 dark:text-slate-400">
                  {count}×
                </span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded bg-slate-100 dark:bg-slate-800">
                <div
                  className="h-full rounded bg-violet-500/70 transition-all duration-500"
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
