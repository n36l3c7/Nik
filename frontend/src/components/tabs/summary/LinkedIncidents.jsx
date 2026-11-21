import { useEffect, useState } from 'react'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { formatNumber } from '../../../domain/incidentName.js'
import { linkedWhy } from '../../../domain/linked.js'
import { api } from '../../../services/api.js'
import { useObjectMenu } from '../../menu/useObjectMenu.js'
import { SeverityTag, StatusTag, Wait } from '../../ui/index.js'

/*
 * ============================================================================
 * LINKED INCIDENTS — what this incident has to do with the others (6.2)
 * ============================================================================
 *
 * The incidents its field "Related incidents" names (or that name it: an
 * incident closed as the duplicate of this one), then those that hold
 * indicators this one holds too, the most shared first: ten at most
 * (GET /api/incidents/<id>/linked). A row opens its incident.
 *
 * A widget of the Summary and of the pages of a type; the quick view of the
 * incident list draws the same list in its narrow column (`compact`).
 */

/**
 * @param {{
 *   incidentId: string,
 *   onOpen?: (id: string) => void,   // open an incident; the active one changes when left out
 *   compact?: boolean,               // one line a row, for a narrow column
 * }} props
 */
export default function LinkedIncidents({ incidentId, onOpen = null, compact = false }) {
  const { selectIncident } = useIncidents()
  const menu = useObjectMenu()
  const [state, setState] = useState({ id: null, found: null, error: null })

  useEffect(() => {
    let alive = true
    api
      .get(`/incidents/${encodeURIComponent(incidentId)}/linked`)
      .then((found) => alive && setState({ id: incidentId, found, error: null }))
      .catch((failure) => alive && setState({ id: incidentId, found: null, error: failure.message }))
    return () => {
      alive = false
    }
  }, [incidentId])

  if (state.id !== incidentId) return <Wait>Loading…</Wait>
  if (state.error) return <p className="text-sm text-fg-muted">This could not be read: {state.error}</p>
  const { incidents, total } = state.found
  if (incidents.length === 0) {
    return (
      <p className="text-sm text-fg-muted">No other incident is related to this one, or holds one of its indicators.</p>
    )
  }
  const open = onOpen ?? selectIncident
  return (
    <div className="flex h-full flex-col gap-1">
      <ul aria-label="Linked incidents" className="min-h-0 flex-1 overflow-y-auto">
        {incidents.map((item) => (
          <li
            key={item.id}
            className="border-b border-line-soft last:border-b-0"
            onContextMenu={(event) =>
              menu(event, {
                title: item.name,
                actions: [{ label: 'Open', onSelect: () => open(item.id) }],
                link: `/incident/${encodeURIComponent(item.id)}`,
                copy: [
                  { label: 'Copy the name', text: item.name },
                  { label: 'Copy the number', text: formatNumber(item.number) },
                ],
              })
            }
          >
            <button
              type="button"
              onClick={() => open(item.id)}
              title={`Open ${item.name}`}
              className="flex w-full flex-wrap items-baseline gap-x-2 gap-y-0.5 px-1 py-1.5 text-left hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent"
            >
              <span className="shrink-0 font-mono text-xs text-fg-muted">{formatNumber(item.number)}</span>
              <span className="min-w-0 flex-1 truncate text-sm text-link">{item.name}</span>
              {item.severity && <SeverityTag severity={item.severity} />}
              <StatusTag status={item.status} />
              {!compact && item.type && <span className="shrink-0 text-xs text-fg-muted">{item.type}</span>}
              <span className={`text-xs text-fg-muted ${compact ? 'w-full truncate' : 'w-full'}`}>
                {linkedWhy(item)}
              </span>
            </button>
          </li>
        ))}
      </ul>
      {total > incidents.length && (
        <p className="shrink-0 text-xs text-fg-muted">
          The first {incidents.length} of {total}.
        </p>
      )}
    </div>
  )
}
