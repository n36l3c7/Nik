import { useIncidents } from '../../context/IncidentContext.jsx'
import { ANALYSIS_TABS } from '../../config/tabs.js'

/*
 * ============================================================================
 * TABBAR — navigation across the analysis tabs (SOC style, cyan underline)
 * ============================================================================
 *
 * Tabs come from the ANALYSIS_TABS registry: adding an entry there makes the
 * tab appear here automatically, without touching this file.
 */

/**
 * @param {{ activeTabId: string, onChange: (tabId: string) => void }} props
 */
export default function TabBar({ activeTabId, onChange }) {
  const { activeIncident } = useIncidents()
  // Without an active incident there is nothing to analyze: tabs are disabled.
  const disabled = !activeIncident

  return (
    <nav
      aria-label="Analysis tabs"
      className="flex shrink-0 gap-1 overflow-x-auto border-b border-slate-200 bg-white px-6 dark:border-slate-800 dark:bg-slate-900"
    >
      {ANALYSIS_TABS.map((tab) => {
        const Icon = tab.icon
        const isActive = tab.id === activeTabId
        return (
          <button
            key={tab.id}
            type="button"
            disabled={disabled}
            onClick={() => onChange(tab.id)}
            aria-current={isActive ? 'page' : undefined}
            className={[
              '-mb-px flex items-center gap-2 whitespace-nowrap border-b-2 px-4 py-3 text-sm font-medium transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500',
              'disabled:cursor-not-allowed disabled:opacity-50',
              isActive
                ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400'
                : 'border-transparent text-slate-500 hover:border-slate-300 hover:text-slate-700 dark:text-slate-400 dark:hover:border-slate-700 dark:hover:text-slate-200',
            ].join(' ')}
          >
            <Icon className="h-4 w-4" />
            {tab.label}
          </button>
        )
      })}
    </nav>
  )
}
