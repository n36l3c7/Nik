import { useState } from 'react'
import { CalendarClock } from 'lucide-react'
import { EXPIRY_CHOICES, expiryDate, expiryText } from '../../domain/artifactExpiry.js'
import { Button } from '../ui/index.js'
import { useUnsavedChanges } from '../../lib/unsaved.js'

/*
 * When an artifact is deleted by itself: never, unless someone gives it a
 * date here. "kept: no expiry", or "expires in 6 days", and a way to set one:
 * in 30 or 90 days, in a year, on a date, or never.
 */

const FIELD =
  'h-7 border border-line bg-canvas px-2 font-mono text-xs text-fg ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/**
 * @param {{
 *   artifact: { expiresAt: string | null, expiresInDays: number | null, expiryNote: string },
 *   onSet: (expiresAt: string | null) => Promise<void>,
 * }} props
 */
export default function ExpiryControl({ artifact, onSet }) {
  const [open, setOpen] = useState(false)
  const [day, setDay] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const tomorrow = expiryDate(1)
  useUnsavedChanges(open && Boolean(day), { what: 'The day the artifact expires', name: artifact?.name })

  const set = async (value) => {
    setBusy(true)
    setError(null)
    try {
      await onSet(value)
      setOpen(false)
      setDay('')
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <span className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
      <span className={`text-sm ${artifact.expiresAt ? 'text-fg' : 'text-fg-muted'}`}>{expiryText(artifact)}</span>
      {!open ? (
        <Button size="xs" variant="ghost" icon={CalendarClock} onClick={() => setOpen(true)}>
          {artifact.expiresAt ? 'Change the expiry…' : 'Set an expiry…'}
        </Button>
      ) : (
        <span role="group" aria-label="When it expires" className="flex flex-wrap items-center gap-1.5">
          {EXPIRY_CHOICES.map((choice) => (
            <Button
              key={choice.label}
              size="xs"
              variant="secondary"
              disabled={busy || (choice.days === null && !artifact.expiresAt)}
              onClick={() => set(choice.days === null ? null : expiryDate(choice.days))}
            >
              {choice.label}
            </Button>
          ))}
          <label className="flex items-center gap-1 text-xs text-fg-muted">
            on
            <input
              type="date"
              aria-label="On a date"
              min={tomorrow}
              value={day}
              onChange={(event) => setDay(event.target.value)}
              className={FIELD}
            />
          </label>
          <Button size="xs" disabled={busy || !day} onClick={() => set(day)}>
            Set
          </Button>
          <Button size="xs" variant="ghost" onClick={() => setOpen(false)}>
            Cancel
          </Button>
        </span>
      )}
      {artifact.expiryNote && <span className="w-full text-xs text-med">{artifact.expiryNote}.</span>}
      {error && (
        <span role="alert" className="w-full text-xs text-high">
          {error}
        </span>
      )}
    </span>
  )
}
