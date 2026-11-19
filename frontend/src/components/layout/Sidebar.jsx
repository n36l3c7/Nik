import ArtifactsPanel from '../artifacts/ArtifactsPanel.jsx'
import IocsPanel from '../iocs/IocsPanel.jsx'

/*
 * ============================================================================
 * SIDEBAR — the panel next to the rail: artifacts or indicators
 * ============================================================================
 *
 * The rail (Rail.jsx) chooses the panel. The list of incidents was a panel
 * here until 6.2; it is a page of its own now
 * (components/incidents/IncidentsPage.jsx).
 */

/**
 * @param {{
 *   panel: 'artifacts' | 'iocs',
 *   onNewAnalysis: () => void,     // opens the "New analysis" dialog owned by App
 *   width?: number,                // pixel width (resizable), defaults to 288
 * }} props
 */
export default function Sidebar({ panel, onNewAnalysis, width = 288 }) {
  if (panel === 'artifacts') return <ArtifactsPanel width={width} onNewAnalysis={onNewAnalysis} />
  if (panel === 'iocs') return <IocsPanel width={width} />
  return null
}
