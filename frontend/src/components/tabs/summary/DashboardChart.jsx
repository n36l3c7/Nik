import { Suspense, lazy, useEffect, useState } from 'react'
import { chartNote, chartPath } from '../../../domain/linked.js'
import { api } from '../../../services/api.js'

// The charts are the dashboards': loaded when a page shows one.
const Widget = lazy(() => import('../../dashboards/Widget.jsx'))

/*
 * ============================================================================
 * CHART OF A DASHBOARD — one widget of a dashboard, narrowed to the incident (6.2)
 * ============================================================================
 *
 * The type chose a widget of a dashboard and ONE field. The server gives that
 * widget with its query narrowed to what this incident holds for the field
 * (GET /api/incidents/<id>/chart), and the widget is drawn as on its
 * dashboard: it asks its own numbers, as the person looking.
 *
 * An incident that holds nothing for the field shows no chart: one of
 * everything would say nothing of this incident. A dashboard that is not
 * shared with the person looking is not theirs to see here either.
 */

const MUTED = 'text-sm text-fg-muted'

/**
 * @param {{ incident: object, widget: object }} props
 */
export default function DashboardChart({ incident, widget }) {
  const path = chartPath(incident.id, widget)
  // Asked again when the incident changes: the value it is narrowed by may have.
  const stamp = incident.updatedAt ?? ''
  const [state, setState] = useState({ key: '', path: '', found: null, error: null })
  const key = `${path}|${stamp}`

  useEffect(() => {
    if (!path) return undefined
    let alive = true
    api
      .get(path)
      .then((found) => alive && setState({ key, path, found, error: null }))
      .catch((failure) => alive && setState({ key, path, found: null, error: failure.message }))
    return () => {
      alive = false
    }
  }, [path, key])

  if (!path) return <p className={MUTED}>No chart was chosen for this widget.</p>
  if (state.error && state.key === key) return <p className={MUTED}>{state.error}.</p>
  // While it is asked again for the same incident the last answer stays: no flash at every save.
  const found = state.path === path ? state.found : null
  if (!found) return <p className={`font-mono ${MUTED}`}>Loading…</p>
  if (found.empty) {
    return (
      <p className={MUTED}>This incident has no {found.field}: the chart would count everything, so it is not drawn.</p>
    )
  }
  return (
    <div className="flex h-full min-h-0 flex-col gap-1">
      <div className="min-h-0 flex-1">
        <Suspense fallback={<p className={`font-mono ${MUTED}`}>Loading…</p>}>
          <Widget widget={found.widget} board={found.board} range={found.board.timeRange} />
        </Suspense>
      </div>
      <p className="shrink-0 truncate text-xs text-fg-muted" title={chartNote(found)}>
        {chartNote(found)}
      </p>
    </div>
  )
}
