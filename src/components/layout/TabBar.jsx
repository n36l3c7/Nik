import { useIncidents } from '../../context/IncidentContext.jsx'
import { ANALYSIS_TABS } from '../../config/tabs.js'

/*
 * ============================================================================
 * TABBAR — navigation across the analysis tabs (terminal style: monospace,
 * green underline, a "›" prompt on the active tab)
 * ============================================================================
 *
 * Tabs come from the ANALYSIS_TABS registry: adding an entry there makes the
 * tab appear here automatically, without touching this file.
 */

/**
 * @param {{ activeTabId: string, onChange: (tabId: string) => void }} props
 */
export default function TabBar({ activeTabId, onChange }) {
  const { activeSummary } = useIncidents()
  // Without an active incident there is nothing to analyze: tabs are disabled.
  // They stay usable while the selected incident is still loading.
  const disabled = !activeSummary

  return (
    <nav
      aria-label="Analysis tabs"
      className="flex shrink-0 gap-1 overflow-x-auto border-b border-line bg-canvas px-6"
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
              '-mb-px flex items-center gap-2 whitespace-nowrap border-b-2 px-3 py-2.5 font-mono text-[13px] transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
              'disabled:cursor-not-allowed disabled:opacity-50',
              isActive
                ? 'border-accent text-fg'
                : 'border-transparent text-fg-muted hover:border-line hover:text-fg',
            ].join(' ')}
          >
            <Icon className={`h-4 w-4 ${isActive ? 'text-accent' : ''}`} aria-hidden="true" />
            {isActive && <span aria-hidden="true" className="-mr-1 text-accent">›</span>}
            {tab.label}
          </button>
        )
      })}
    </nav>
  )
}
