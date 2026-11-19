import { useState } from 'react'
import { ChevronDown, ChevronLeft, ChevronRight, ChevronUp, Pencil } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { useFields } from '../../context/FieldsContext.jsx'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { api } from '../../services/api.js'
import { panelSection, typeOf, valuesOf } from '../../domain/fields.js'
import { Badge, Button } from '../ui/index.js'
import EditFieldsDialog from './EditFieldsDialog.jsx'
import FieldList from './FieldList.jsx'
import Mirror from './Mirror.jsx'
import Timers from './Timers.jsx'
import ResizeHandle, { useResizablePane } from '../ui/ResizeHandle.jsx'

/*
 * ============================================================================
 * THE SIDE PANEL OF AN INCIDENT — its type and its key facts, always in view
 * ============================================================================
 *
 * A column to the left of the tabs (250 px) with the incident's type and the
 * fields of the section its type flags as the side panel. It stays while the
 * tabs change, so the status, the severity and who has the incident are in
 * view from the Timeline as from the Summary. It can be folded, which a wide
 * tab (a timeline, a graph) wants; folded or not is remembered in this
 * browser. Below 1100 px it is a band above the tabs.
 *
 * "Edit" opens a form for its fields; the type is changed from its select.
 * Both go through the field registry, which checks them.
 */

const FOLDED_KEY = 'nik.incidentPanel.folded'

/**
 * @param {{ incident: object }} props
 */
export default function IncidentPanel({ incident }) {
  const { can } = useAuth()
  const { types, known, ready } = useFields()
  const { refreshIncidents, retryActiveIncident } = useIncidents()
  const [folded, setFoldedState] = useState(() => localStorage.getItem(FOLDED_KEY) === '1')
  const [editing, setEditing] = useState(false)
  const pane = useResizablePane('incident.facts', { initial: 250, min: 220, max: 480 })
  const [error, setError] = useState(null)
  const canWrite = can('write')

  const setFolded = (next) => {
    setFoldedState(next)
    localStorage.setItem(FOLDED_KEY, next ? '1' : '')
  }

  const type = typeOf(types, incident)
  const section = panelSection(type)
  if (!ready || !type || !section) return null
  const fields = section.fields.map((name) => known[name]).filter(Boolean)
  const values = valuesOf(incident)

  const changeType = async (id) => {
    setError(null)
    try {
      await api.patch(`/incidents/${encodeURIComponent(incident.id)}/fields`, { changes: { type: id } })
      refreshIncidents()
      retryActiveIncident()
    } catch (failure) {
      setError(failure.message)
    }
  }

  if (folded) {
    return (
      <aside
        aria-label="Incident facts"
        className="flex shrink-0 items-center gap-2 border-b border-line bg-panel px-3 py-1.5 min-[1100px]:w-9 min-[1100px]:flex-col min-[1100px]:border-b-0 min-[1100px]:border-r min-[1100px]:px-0 min-[1100px]:py-3"
      >
        <button
          type="button"
          aria-label="Show the incident's facts"
          aria-expanded="false"
          title="Show the incident's facts"
          onClick={() => setFolded(false)}
          className="text-fg-muted hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <ChevronRight className="hidden h-4 w-4 min-[1100px]:block" aria-hidden="true" />
          <ChevronDown className="h-4 w-4 min-[1100px]:hidden" aria-hidden="true" />
        </button>
        <span className="font-mono text-[11px] uppercase tracking-wider text-fg-muted min-[1100px]:hidden">
          {type.name} · facts
        </span>
      </aside>
    )
  }

  return (
    <>
      <aside
        aria-label="Incident facts"
        style={pane.style}
        className="flex shrink-0 flex-col gap-3 overflow-y-auto border-b border-line bg-panel p-3 min-[1100px]:w-[var(--pane-w)] min-[1100px]:border-b-0 min-[1100px]:border-r"
      >
        <div className="flex items-center gap-2">
          <Badge color={type.colour}>{type.name}</Badge>
          <span className="flex-1" />
          {canWrite && fields.length > 0 && (
            <Button variant="ghost" size="xs" icon={Pencil} onClick={() => setEditing(true)}>
              Edit
            </Button>
          )}
          <button
            type="button"
            aria-label="Hide the incident's facts"
            aria-expanded="true"
            title="Hide the incident's facts"
            onClick={() => setFolded(true)}
            className="text-fg-muted hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <ChevronLeft className="hidden h-4 w-4 min-[1100px]:block" aria-hidden="true" />
            <ChevronUp className="h-4 w-4 min-[1100px]:hidden" aria-hidden="true" />
          </button>
        </div>
        {canWrite && types.length > 1 && (
          <label className="flex flex-col gap-0.5" htmlFor="incident-type">
            <span className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">Type</span>
            <select
              id="incident-type"
              value={type.id}
              onChange={(event) => changeType(event.target.value)}
              className="w-full cursor-pointer border border-line bg-canvas px-2 py-1 text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              {types.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))}
            </select>
          </label>
        )}
        {error && (
          <p role="alert" className="text-xs text-high-fg">
            {error}
          </p>
        )}
        {/* As a band above the tabs the facts are side by side; as a column, one under the other. */}
        <FieldList
          fields={fields}
          values={values}
          dense
          className="grid-cols-2 sm:grid-cols-3 min-[1100px]:grid-cols-1"
        />
        <Timers incident={incident} />
        <Mirror incident={incident} />
        {editing && (
          <EditFieldsDialog
            incident={incident}
            type={type}
            title={section.title}
            fields={fields}
            values={values}
            onClose={() => setEditing(false)}
          />
        )}
      </aside>
      <ResizeHandle {...pane.handle} label="Resize the incident's facts" className="hidden min-[1100px]:block" />
    </>
  )
}
