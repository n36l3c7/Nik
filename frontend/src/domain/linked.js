/*
 * Two widgets of an incident page that ask the server (6.2): the incidents
 * linked to one (GET /api/incidents/<id>/linked) and a chart of a dashboard
 * narrowed to it (GET /api/incidents/<id>/chart). What is here is what they
 * say of what the server answered.
 */

const list = (value) => (Array.isArray(value) ? value : [])

/**
 * Why an incident is linked to the one on screen: "related", "shares 2
 * indicators: 185.220.101.47, inv0ice.example", or both.
 */
export function linkedWhy(item) {
  const parts = []
  if (item?.related) parts.push('related')
  const shared = Number(item?.shared) || 0
  if (shared > 0) {
    const named = list(item.indicators)
      .map((indicator) => indicator?.value)
      .filter(Boolean)
    const more = shared - named.length
    parts.push(
      `shares ${shared} ${shared === 1 ? 'indicator' : 'indicators'}` +
        (named.length > 0 ? `: ${named.join(', ')}${more > 0 ? ` and ${more} more` : ''}` : ''),
    )
  }
  return parts.join(' · ')
}

/** The address of the chart of a widget for an incident (null while the widget names no chart). */
export function chartPath(incidentId, widget) {
  if (!incidentId || !widget?.dashboard || !widget?.widget) return null
  const query = new URLSearchParams({ dashboard: widget.dashboard, widget: widget.widget, field: widget.field ?? '' })
  return `/incidents/${encodeURIComponent(incidentId)}/chart?${query}`
}

/** What a value of the incident reads as in a line: "WS-0231", "a, b". */
export const chartValue = (value) => (Array.isArray(value) ? value.join(', ') : String(value ?? ''))

/** The line under a chart: what it was narrowed to. */
export function chartNote(found) {
  if (!found) return ''
  return `${found.board?.name ?? 'A dashboard'} · narrowed to ${found.field}: ${chartValue(found.value)}`
}

/**
 * The widgets of a dashboard a page of a type can show: those that ask a
 * query (a text, the disk and the fetch health have nothing to narrow).
 */
export const NARROWABLE = new Set(['number', 'trend', 'bar', 'stacked_bar', 'pie', 'top', 'table', 'duration', 'gauge'])
export const chartWidgets = (board) => list(board?.widgets).filter((widget) => NARROWABLE.has(widget?.type))

/** What the editor of a type says of a chart widget: "SOC overview / By severity · host". */
export function chartSummary(widget, boards) {
  if (!widget?.dashboard || !widget?.widget) return 'No chart was chosen yet.'
  const board = list(boards).find((item) => item.id === widget.dashboard)
  const chosen = list(board?.widgets).find((item) => item.id === widget.widget)
  const name = board ? `${board.name} / ${chosen?.title || chosen?.type || 'a widget that is gone'}` : 'A chart'
  return widget.field ? `${name} · narrowed by ${widget.field}` : `${name} · no field chosen yet`
}
