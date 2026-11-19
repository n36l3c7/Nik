import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { useAuth } from '../../context/AuthContext.jsx'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { visibleTabs } from '../../config/tabs.js'

/*
 * ============================================================================
 * TABBAR — navigation across the tabs of an incident (terminal style: monospace,
 * green underline, a "›" prompt on the active tab)
 * ============================================================================
 *
 * Tabs come from the ANALYSIS_TABS registry: an entry there that is not a kind
 * of evidence appears here, without touching this file (the kinds of evidence
 * are listed inside the Evidence tab). A thin rule separates the registry's
 * groups, when the tabs shown are of more than one.
 *
 * The bar never scrolls sideways while it can avoid it: when the full labels
 * do not fit it switches to the one-word labels, then to icons only, and
 * when even the icons do not fit in one row it takes a second one. The
 * active tab always shows its full label, and every tab keeps its full name
 * for assistive technology and as a tooltip.
 */

const FULL = 0
const SHORT = 1
// 2: icons only.
const ROWS = 3

/**
 * @param {{
 *   activeTabId: string,
 *   onChange: (tabId: string) => void,
 *   tabs?: object[],       // the tabs to show, in order (those of the incident's type); every visible one otherwise
 * }} props
 */
export default function TabBar({ activeTabId, onChange, tabs: given = null }) {
  const { activeSummary } = useIncidents()
  const { can } = useAuth()
  // A tab that needs a permission is shown to the accounts that hold it.
  const tabs = given ?? visibleTabs(can)
  // Without an active incident there is nothing to analyze: tabs are disabled.
  // They stay usable while the selected incident is still loading.
  const disabled = !activeSummary

  const navRef = useRef(null)
  const [density, setDensity] = useState(FULL)
  const [width, setWidth] = useState(0)

  // A new width starts again from the full labels…
  useEffect(() => {
    const nav = navRef.current
    if (!nav || typeof ResizeObserver === 'undefined') return undefined
    const observer = new ResizeObserver(([entry]) => {
      const next = Math.round(entry.contentRect.width)
      setWidth((previous) => {
        if (previous !== next) setDensity(FULL)
        return next
      })
    })
    observer.observe(nav)
    return () => observer.disconnect()
  }, [])

  // …and steps down while the tabs still overflow.
  useLayoutEffect(() => {
    const nav = navRef.current
    if (nav && density < ROWS && nav.scrollWidth > nav.clientWidth + 1) setDensity(density + 1)
  }, [density, width, activeTabId])

  return (
    <nav
      ref={navRef}
      aria-label="Analysis tabs"
      className={`flex shrink-0 gap-1 overflow-x-auto border-b border-line bg-canvas px-6 ${density === ROWS ? 'flex-wrap' : ''}`}
    >
      {tabs.map((tab, index) => {
        const Icon = tab.icon
        const isActive = tab.id === activeTabId
        // A rule between the groups of the registry; a type that orders its tabs draws none.
        const newGroup = !given?.ordered && index > 0 && tab.group !== tabs[index - 1].group
        const text = isActive || density === FULL ? tab.label : density === SHORT ? tab.short : null
        return [
          newGroup && (
            <span
              key={`${tab.id}-rule`}
              aria-hidden="true"
              className={`my-2.5 w-px shrink-0 bg-line ${density === FULL ? 'mx-2' : 'mx-1'}`}
            />
          ),
          <button
            key={tab.id}
            type="button"
            disabled={disabled}
            onClick={() => onChange(tab.id)}
            aria-current={isActive ? 'page' : undefined}
            aria-label={tab.label}
            title={text === tab.label ? undefined : tab.label}
            className={[
              '-mb-px flex shrink-0 items-center gap-2 whitespace-nowrap border-b-2 py-2.5 font-mono text-[13px] transition-colors',
              density === FULL ? 'px-3' : 'px-2',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
              'disabled:cursor-not-allowed disabled:opacity-50',
              isActive ? 'border-accent text-fg' : 'border-transparent text-fg-muted hover:border-line hover:text-fg',
            ].join(' ')}
          >
            <Icon className={`h-4 w-4 ${isActive ? 'text-accent' : ''}`} aria-hidden="true" />
            {isActive && (
              <span aria-hidden="true" className="-mr-1 text-accent">
                ›
              </span>
            )}
            {text}
          </button>,
        ]
      })}
    </nav>
  )
}
