import { useMemo } from 'react'
import { IocValue } from '../../context/IocLookupContext.jsx'
import { indicatorSegments } from '../../domain/iocs.js'

/**
 * A line of evidence with its indicators made clickable: a public address, a
 * host name, a URL or a hash opens the indicator's window (and has the usual
 * right-click menu). Private addresses and the rest of the line stay text.
 *
 * @param {{ text: string, hint?: 'ip' | 'domain' | 'url' | null, className?: string }} props
 */
export default function IocText({ text, hint = null, className = '' }) {
  const parts = useMemo(() => indicatorSegments(text, hint), [text, hint])
  if (parts.length === 1 && !parts[0].type) return <span className={className}>{text}</span>
  return (
    <span className={className}>
      {parts.map((part, index) =>
        part.type ? <IocValue key={index} type={part.type} value={part.text} /> : <span key={index}>{part.text}</span>,
      )}
    </span>
  )
}
