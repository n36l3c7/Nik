import { useAuth } from '../context/AuthContext.jsx'
import { useIncidents } from '../context/IncidentContext.jsx'

/**
 * Whether the account may change what is on screen: it holds `write`, and the incident is not archived
 * (an archived incident is read-only for everybody, the server refuses its writes). `incident` is the one
 * the component shows; without it, the incident that is open.
 */
export function useCanWrite(incident = null) {
  const { can } = useAuth()
  const { activeIncident } = useIncidents()
  const shown = incident ?? activeIncident
  return can('write') && !shown?.archivedAt
}
