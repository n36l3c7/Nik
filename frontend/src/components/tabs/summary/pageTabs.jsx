import { lazy } from 'react'
import { LayoutGrid } from 'lucide-react'
import { pageName, pageTabId, pagesOf } from '../../../domain/typePages.js'

/*
 * The pages a type adds to its incidents (6.2), as tabs of the incident page:
 * what config/tabs.js is for the tabs of Nik. The page itself is loaded when
 * one is opened, like every tab.
 */

const TypePageTab = lazy(() => import('./TypePageTab.jsx'))

// One component for each page, made once: the tab bar tells tabs apart by what draws them.
const components = new Map()
function componentOf(pageId) {
  if (!components.has(pageId)) {
    const Page = (props) => <TypePageTab {...props} pageId={pageId} />
    Page.displayName = `TypePage(${pageId})`
    components.set(pageId, Page)
  }
  return components.get(pageId)
}

/** The pages of a layout as tabs of the incident page (config/tabs.js says what a tab is). */
export function pageTabs(layout) {
  return pagesOf(layout).map((page) => ({
    id: pageTabId(page.id),
    label: pageName(page),
    short: pageName(page),
    group: 'overview',
    icon: LayoutGrid,
    component: componentOf(page.id),
  }))
}
