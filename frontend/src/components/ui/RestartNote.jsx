import { workLine, workProgress } from '../../domain/restarts.js'
import { formatDateTime } from '../../lib/time.js'

/*
 * What a job says of itself beside its state: how far its worker is, and
 * what a restart of the server did to it ("Interrupted by a restart at …,
 * started again at …"). Nothing is drawn for a job no restart touched and
 * whose worker says nothing.
 */

/**
 * @param {{ work?: object | null, className?: string }} props
 *   `work` as the server gives it with a job: { state, attempts, interruptedAt, resumedAt, progress }.
 */
export default function RestartNote({ work, className = '' }) {
  const progress = workProgress(work)
  const restart = workLine(work, formatDateTime)
  if (!progress && !restart) return null
  return (
    <p className={`font-mono text-xs text-fg-muted ${className}`}>
      {progress ? <span>The worker says: {progress}. </span> : null}
      {restart}
    </p>
  )
}
