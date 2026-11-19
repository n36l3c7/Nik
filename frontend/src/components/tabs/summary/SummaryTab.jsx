import { useMemo } from 'react'
import { useFields } from '../../../context/FieldsContext.jsx'
import { typeOf } from '../../../domain/fields.js'
import { gridOf, widgetTitle } from '../../../domain/layoutGrid.js'
import Grid from '../../dashboards/Grid.jsx'
import LayoutWidget from './LayoutWidgets.jsx'

/*
 * ============================================================================
 * SUMMARY TAB — the page the type of the incident arranges
 * ============================================================================
 *
 * A grid of widgets, as a dashboard is: the details of the incident, its
 * sections of fields, the numbers of its evidence, its flags and notes, and
 * whatever else the type put there (the War Room, the work plan, timers,
 * indicators, evidence, playbook buttons, a text). The grid is the type's
 * (Settings → Incidents → Types → The page); a type that arranged none shows
 * what the Summary showed before 5.3, in the same order.
 *
 * The incident itself (its ticket, title, severity, status, owner, host, user,
 * system, suspicious window) is changed in "Edit the incident", which the
 * details widget opens.
 */

const NOTHING = () => {}

/**
 * @param {{ incident: object }} props
 */
export default function SummaryTab({ incident }) {
  const { types } = useFields()
  const type = typeOf(types, incident)
  const widgets = useMemo(
    () =>
      gridOf(type).grid.map((widget) => ({
        ...widget,
        // The grid of the dashboards names a widget by its title and its type.
        type: widget.kind,
        title: widgetTitle(widget, type?.layout),
      })),
    [type],
  )
  return (
    <div aria-label="Summary of the incident" role="region">
      <Grid
        widgets={widgets}
        editing={false}
        onChange={NOTHING}
        onEdit={NOTHING}
        onDuplicate={NOTHING}
        onRemove={NOTHING}
        render={(widget) => <LayoutWidget widget={widget} incident={incident} type={type} />}
      />
    </div>
  )
}
