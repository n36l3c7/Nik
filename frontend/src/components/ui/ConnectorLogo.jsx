import { apiUrl } from '../../services/api.js'

/**
 * The logo of the connector that brought an incident in, to tell its source at
 * a glance. Nothing is drawn for an incident made here, nor for a connector
 * that has no logo: Nik's own mark is never a placeholder.
 *
 * @param {{ source?: { connector?: string, connection?: string, logo?: string | null } | null, className?: string }} props
 */
export default function ConnectorLogo({ source, className = 'h-4 w-4' }) {
  if (!source?.logo) return null
  const from = [source.connector, source.connection].filter(Boolean).join(' · ')
  return (
    <img
      src={apiUrl(source.logo)}
      alt={source.connector ? `From ${source.connector}` : 'From a connector'}
      title={from ? `Brought in by ${from}` : undefined}
      className={`shrink-0 object-contain ${className}`}
    />
  )
}
