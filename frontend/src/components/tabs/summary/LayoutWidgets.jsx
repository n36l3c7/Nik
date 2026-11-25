import { Suspense, useMemo, useState } from 'react'
import { Pencil } from 'lucide-react'
import { useFields } from '../../../context/FieldsContext.jsx'
import { useNavigation } from '../../../context/NavigationContext.jsx'
import { ANALYSIS_TABS, getTabById } from '../../../config/tabs.js'
import { getOsById } from '../../../config/os.js'
import { evidenceGroups, hostCounts } from '../../../domain/evidence.js'
import { IN_SUMMARY_FORM, valuesOf } from '../../../domain/fields.js'
import { STATUSES } from '../../../domain/incidentName.js'
import { gridSections, kindOf } from '../../../domain/layoutGrid.js'
import { chartSummary } from '../../../domain/linked.js'
import { formatDateTime } from '../../../lib/time.js'
import { useCanWrite } from '../../../lib/useCanWrite.js'
import { useEvidenceSummary } from '../../../lib/useEvidenceSummary.js'
import { Button, ErrorBoundary, SeverityTag, Wait } from '../../ui/index.js'
import EditFieldsDialog from '../../fields/EditFieldsDialog.jsx'
import FieldList from '../../fields/FieldList.jsx'
import Timers from '../../fields/Timers.jsx'
import EditIncidentDialog from '../../incident/EditIncidentDialog.jsx'
import DashboardChart from './DashboardChart.jsx'
import IncidentTimeline from './IncidentTimeline.jsx'
import LinkedIncidents from './LinkedIncidents.jsx'
import ScriptButtons from './ScriptButtons.jsx'

/*
 * ============================================================================
 * The widgets of the Summary: what each kind of the grid draws (5.3)
 * ============================================================================
 *
 * A widget is given the incident and its type and fills the box the grid
 * gives it: what does not fit scrolls inside the box, as on a dashboard.
 * The kinds are in domain/layoutGrid.js; a kind this file does not know is
 * drawn as an empty box that says so, never as an error.
 */

const MUTED = 'text-sm text-fg-muted'
const TERM = 'font-mono text-[11px] uppercase tracking-wider text-fg-muted'
// The button of a widget stands in the line of its title, which the grid draws: the box is left to what it shows.
const IN_TITLE = 'absolute -top-8 right-0 flex h-8 items-center'

function Line({ label, children }) {
  return (
    <div className="flex gap-3">
      <dt className={`w-28 shrink-0 pt-0.5 ${TERM}`}>{label}</dt>
      <dd className="min-w-0 flex-1 break-words text-sm text-fg">{children}</dd>
    </div>
  )
}

/** What the incident is, with the button that edits it. */
function Facts({ incident }) {
  const canWrite = useCanWrite(incident)
  const [editing, setEditing] = useState(false)
  const status = STATUSES.find((item) => item.value === (incident.status ?? 'open'))?.label ?? incident.status
  const window = [incident.suspiciousStart, incident.suspiciousEnd]
    .map((ms) => (Number.isFinite(ms) ? formatDateTime(ms) : '…'))
    .join(' → ')
  return (
    <div className="flex h-full flex-col gap-2">
      <dl className="grid min-h-0 flex-1 content-start gap-x-6 gap-y-1.5 overflow-y-auto @md:grid-cols-2">
        <Line label="Name">{incident.name}</Line>
        <Line label="Ticket">{incident.ticketId || '—'}</Line>
        <Line label="Severity">{incident.severity ? <SeverityTag severity={incident.severity} /> : '—'}</Line>
        <Line label="Status">{status}</Line>
        <Line label="Assigned to">{incident.assignee || 'nobody'}</Line>
        <Line label="Host">{incident.host || '—'}</Line>
        <Line label="User">{incident.username || '—'}</Line>
        <Line label="System">{getOsById(incident.os)?.label ?? 'not set'}</Line>
        <Line label="Suspicious">
          {Number.isFinite(incident.suspiciousStart) || Number.isFinite(incident.suspiciousEnd) ? window : '—'}
        </Line>
        <Line label="Created">
          {incident.createdBy || 'unknown'} · {formatDateTime(Date.parse(incident.createdAt))}
        </Line>
      </dl>
      {canWrite && (
        <div className={IN_TITLE}>
          <Button variant="ghost" size="xs" icon={Pencil} onClick={() => setEditing(true)}>
            Edit the incident
          </Button>
        </div>
      )}
      {editing && <EditIncidentDialog incident={incident} onClose={() => setEditing(false)} />}
    </div>
  )
}

/** One section of the type, with its fields and the form that edits them. */
function Section({ incident, type, widget }) {
  const canWrite = useCanWrite(incident)
  const { known } = useFields()
  const [editing, setEditing] = useState(false)
  const section = gridSections(type?.layout).find((item) => item.id === widget.section)
  // The fields the form of the incident edits are in the details, not here.
  const fields = (section?.fields ?? [])
    .filter((name) => known[name] && !IN_SUMMARY_FORM.includes(name))
    .map((name) => known[name])
  const values = valuesOf(incident)
  if (!section) return <p className={MUTED}>This section is no longer in the type.</p>
  if (fields.length === 0) return <p className={MUTED}>No field in this section yet.</p>
  return (
    <div className="flex h-full flex-col gap-2">
      <div className="min-h-0 flex-1 overflow-y-auto">
        <FieldList fields={fields} values={values} columns={section.columns} />
      </div>
      {canWrite && (
        <div className={IN_TITLE}>
          <Button
            variant="ghost"
            size="xs"
            icon={Pencil}
            aria-label={`Edit ${section.title}`}
            onClick={() => setEditing(true)}
          >
            Edit
          </Button>
        </div>
      )}
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
    </div>
  )
}

/** How much evidence the incident holds. */
function Stats({ incident }) {
  // What the machine gave is counted by the server (the document holds none of it).
  const { summary } = useEvidenceSummary(incident.id)
  const figures = useMemo(
    () => [
      ['Event logs', hostCounts(summary, 'eventlogs').records],
      ['Browser records', hostCounts(summary, 'browser').records],
      ['Commands', hostCounts(summary, 'commands').records],
      ['Endpoint artifacts', hostCounts(summary, 'endpoint').records],
      ['Flagged', Object.keys(incident.flags ?? {}).length],
      ['Notes', incident.notes?.length ?? 0],
    ],
    [summary, incident.flags, incident.notes],
  )
  return (
    <dl className="grid h-full grid-cols-2 content-start gap-2 overflow-y-auto @xs:grid-cols-3">
      {figures.map(([label, value]) => (
        <div key={label} className="border border-line-soft bg-canvas px-3 py-2">
          <dd className={`font-mono text-xl ${label === 'Flagged' && value > 0 ? 'text-accent' : 'text-fg'}`}>
            {value}
          </dd>
          <dt className={TERM}>{label}</dt>
        </div>
      ))}
    </dl>
  )
}

/** The files of the incident, kind by kind: each opens in the Evidence tab. */
function Evidence({ incident }) {
  const { goTo } = useNavigation()
  const { summary } = useEvidenceSummary(incident.id)
  const groups = useMemo(
    () =>
      evidenceGroups(
        ANALYSIS_TABS.filter((tab) => tab.evidence),
        incident,
        summary,
      ).filter((group) => group.count > 0),
    [incident, summary],
  )
  if (groups.length === 0) return <p className={MUTED}>No evidence yet: drop a file anywhere in the window.</p>
  return (
    <ul className="h-full overflow-y-auto text-sm">
      {groups.map((group) => (
        <li key={group.id} className="py-0.5">
          <button
            type="button"
            onClick={() => goTo(group.id)}
            className="flex w-full items-baseline gap-2 text-left text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <span className="min-w-0 flex-1 truncate">{group.label}</span>
            <span className="shrink-0 font-mono text-xs text-fg-muted">{group.count}</span>
          </button>
          {group.items.length > 0 && (
            <ul className="pl-3 text-xs text-fg-muted">
              {group.items.slice(0, 6).map((file) => (
                <li key={file.key} className="truncate" title={file.name}>
                  {file.name}
                </li>
              ))}
              {group.items.length > 6 && <li>and {group.items.length - 6} more</li>}
            </ul>
          )}
        </li>
      ))}
    </ul>
  )
}

/** A tab of the incident inside a box of the grid. */
function Tab({ id, incident, ...rest }) {
  const Component = getTabById(id)?.component
  if (!Component) return null
  return (
    <div className="h-full overflow-y-auto">
      <Suspense fallback={<Wait>Loading…</Wait>}>
        <Component incident={incident} {...rest} />
      </Suspense>
    </div>
  )
}

const DRAW = {
  facts: (props) => <Facts {...props} />,
  section: (props) => <Section {...props} />,
  stats: (props) => <Stats {...props} />,
  timeline: ({ incident }) => (
    <div className="h-full overflow-y-auto">
      <IncidentTimeline incident={incident} />
    </div>
  ),
  timers: ({ incident }) => (
    <div className="h-full overflow-y-auto">
      <Timers incident={incident} />
    </div>
  ),
  evidence: (props) => <Evidence {...props} />,
  war_room: ({ incident }) => <Tab id="war_room" incident={incident} boxed />,
  work_plan: ({ incident }) => <Tab id="work_plan" incident={incident} />,
  indicators: ({ incident }) => <Tab id="iocs" incident={incident} />,
  buttons: (props) => <ScriptButtons {...props} />,
  chart: (props) => <DashboardChart {...props} />,
  linked: ({ incident }) => <LinkedIncidents incidentId={incident.id} />,
  note: ({ widget }) => (
    <p className="h-full overflow-y-auto whitespace-pre-wrap break-words text-sm text-fg">
      {widget.text || <span className="text-fg-muted">An empty text.</span>}
    </p>
  ),
}

/**
 * @param {{ widget: object, incident: object, type: object | null }} props
 */
export default function LayoutWidget({ widget, incident, type }) {
  const draw = DRAW[widget.kind]
  if (!draw) return <p className={MUTED}>This version of Nik does not know this widget.</p>
  return (
    <ErrorBoundary resetKey={`${incident.id}:${widget.id}`}>
      <div className="@container relative h-full">{draw({ widget, incident, type })}</div>
    </ErrorBoundary>
  )
}

/** The same widgets as the editor of a type shows them: what each is, with no incident behind it. */
export function WidgetPreview({ widget, layout, boards = null }) {
  if (widget.kind === 'note') {
    return <p className="h-full overflow-hidden whitespace-pre-wrap break-words text-sm text-fg">{widget.text}</p>
  }
  if (widget.kind === 'section') {
    const section = gridSections(layout).find((item) => item.id === widget.section)
    return (
      <p className="h-full overflow-hidden font-mono text-xs text-fg-muted">
        {(section?.fields ?? []).join(' · ') || 'No field in this section yet.'}
      </p>
    )
  }
  if (widget.kind === 'buttons') {
    const buttons = widget.buttons ?? []
    if (buttons.length === 0) return <p className="text-xs text-fg-muted">No button yet: the pencil adds one.</p>
    return (
      <div className="flex h-full flex-wrap content-start gap-1.5 overflow-hidden">
        {buttons.map((button, index) => (
          <span
            key={`${button.label}:${index}`}
            style={{ backgroundColor: button.background, color: button.color }}
            className="inline-flex h-6 max-w-full items-center px-2 text-xs font-medium"
          >
            <span className="truncate">{button.label}</span>
          </span>
        ))}
      </div>
    )
  }
  if (widget.kind === 'chart') {
    return <p className="font-mono text-xs text-fg-muted">{chartSummary(widget, boards)}</p>
  }
  // The rest is drawn from the incident: here, what it will show.
  return <p className="text-xs text-fg-muted">{kindOf(widget.kind)?.hint}</p>
}
