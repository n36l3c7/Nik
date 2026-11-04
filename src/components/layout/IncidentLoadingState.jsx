import { Spinner } from '../ui/index.js'

/**
 * ============================================================================
 * INCIDENT LOADING STATE — shown while an incident's full document downloads
 * ============================================================================
 * Non-blocking: it only fills the main area, so the sidebar, header and tab
 * bar stay usable (opening another incident cancels this download). The
 * skeleton mirrors the shape of a tab (stat cards + a table) to avoid a
 * layout jump when the data arrives.
 *
 * @param {{ name: string }} props  Display name of the incident being loaded.
 */
export default function IncidentLoadingState({ name }) {
  return (
    <div aria-busy="true" className="space-y-6">
      <div className="flex items-center gap-3 text-sm text-slate-500 dark:text-slate-400">
        <Spinner className="h-4 w-4" />
        <span>
          Loading <span className="font-medium text-slate-700 dark:text-slate-200">{name}</span>…
        </span>
      </div>
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="h-20 animate-pulse rounded-xl bg-slate-200/70 dark:bg-slate-800/70" />
        ))}
      </div>
      <div className="space-y-2 rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
        {[0, 1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="h-6 animate-pulse rounded bg-slate-200/70 dark:bg-slate-800/70" />
        ))}
      </div>
    </div>
  )
}
