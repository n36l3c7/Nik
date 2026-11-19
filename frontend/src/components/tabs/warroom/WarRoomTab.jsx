import { useMemo } from 'react'
import { useAuth } from '../../../context/AuthContext.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { lineKind } from '../../../domain/commandLine.js'
import { FILTERS } from '../../../domain/warRoom.js'
import Room from '../../room/Room.jsx'

/*
 * ============================================================================
 * WAR ROOM — everything said and done on this incident, in the order it happened
 * ============================================================================
 *
 * Notes, the steps playbooks ran here, approvals answered, commands and what
 * they gave; a line to write in, where `/note`, `/assign @user` and `/close`
 * are what they say. The screen is the Room (components/room/Room.jsx), which
 * the Playground uses too: here it reads and writes the incident.
 *
 * The Timeline is another thing: the forensic timeline of the evidence.
 */

/**
 * @param {{ incident: object, boxed?: boolean }} props   // boxed: inside a widget of the Summary, as tall as it
 */
export default function WarRoomTab({ incident, boxed = false }) {
  const { can } = useAuth()
  const { retryActiveIncident, refreshIncidents, askClose } = useIncidents()
  const canWrite = can('write')
  const canRun = can('automation.run')
  const source = useMemo(
    () => ({
      id: 'war-room',
      label: 'War Room',
      pane: 'warroom.entry',
      className: boxed ? 'h-full min-h-[240px] border border-line' : undefined,
      base: `/incidents/${encodeURIComponent(incident.id)}/war-room`,
      filters: FILTERS,
      canWrite,
      canRun,
      canMark: canWrite,
      placeholder: 'Write a note, or ! for a command, / for /note /assign /close',
      empty: 'Nothing here yet. What is written below, and what playbooks do on this incident, appears here.',
      onLine: (line, answer) => {
        if (answer?.action === 'close') {
          askClose(incident.id)
          return true
        }
        // A note, a new owner: the copy of the incident held here is read again.
        if (lineKind(line) !== 'command') {
          refreshIncidents()
          retryActiveIncident()
        }
        return false
      },
    }),
    [incident.id, boxed, canWrite, canRun, askClose, refreshIncidents, retryActiveIncident],
  )
  return <Room source={source} />
}
