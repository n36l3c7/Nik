import { useMemo } from 'react'
import { useFields } from '../../../context/FieldsContext.jsx'
import { typeOf } from '../../../domain/fields.js'
import { gridOf } from '../../../domain/layoutGrid.js'
import PageGrid from './PageGrid.jsx'

/*
 * ============================================================================
 * SUMMARY TAB — the page the type of the incident arranges
 * ============================================================================
 *
 * A grid of widgets, as a dashboard is: the details of the incident, its
 * sections of fields, the numbers of its evidence, its flags and notes, and
 * whatever else the type put there (the War Room, the work plan, timers,
 * indicators, evidence, script buttons, a chart of a dashboard, the linked
 * incidents, a text). The grid is the type's (Settings → Incidents → Types →
 * Pages); a type that arranged none shows what the Summary showed before 5.3,
 * in the same order.
 *
 * The incident itself (its ticket, title, severity, status, owner, host, user,
 * system, suspicious window) is changed in "Edit the incident", which the
 * details widget opens.
 */

/**
 * @param {{ incident: object }} props
 */
export default function SummaryTab({ incident }) {
  const { types } = useFields()
  const type = typeOf(types, incident)
  const grid = useMemo(() => gridOf(type).grid, [type])
  return <PageGrid incident={incident} type={type} grid={grid} label="Summary of the incident" />
}
