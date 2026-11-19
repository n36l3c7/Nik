import { useFields } from '../../../context/FieldsContext.jsx'
import { typeOf } from '../../../domain/fields.js'
import { pageName, pageOf } from '../../../domain/typePages.js'
import PageGrid from './PageGrid.jsx'

/*
 * ============================================================================
 * A PAGE OF THE TYPE — a tab of the incident its type added (6.2)
 * ============================================================================
 *
 * A type of incident has pages of its own beside the Summary (Settings →
 * Incidents → Types → Pages): each is a name and a grid of the same widgets.
 * On the incident each is a tab, named `page:<id>`, in the place the type
 * gives it among the others.
 */

/**
 * @param {{ incident: object, pageId: string }} props
 */
export default function TypePageTab({ incident, pageId }) {
  const { types } = useFields()
  const type = typeOf(types, incident)
  const page = pageOf(type?.layout, pageId)
  if (!page) return <p className="text-sm text-fg-muted">This page is no longer in the type of the incident.</p>
  if (page.grid.length === 0) {
    return (
      <p role="status" className="text-sm text-fg-muted">
        Nothing was put on this page yet. Its widgets are chosen in Settings, Incidents, Types.
      </p>
    )
  }
  return <PageGrid incident={incident} type={type} grid={page.grid} label={`${pageName(page)} of the incident`} />
}
