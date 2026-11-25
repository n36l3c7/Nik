import { useCallback, useEffect, useState } from 'react'
import { Save } from 'lucide-react'
import { DAYS_RANGE, daysProblem } from '../../../domain/archive.js'
import { api } from '../../../services/api.js'
import { useUnsavedChanges } from '../../../lib/unsaved.js'
import { ErrorNote } from '../../auth/SecondFactorParts.jsx'
import { Button, Wait } from '../../ui/index.js'
import Switch from './Switch.jsx'

/*
 * Incidents → Archiving (who archives incidents).
 *
 * The rule that archives the incidents closed for long (GET/PUT /api/settings/archive): off by default;
 * when on, an incident closed for more than the days below is archived by the hourly housekeeping, as `nik`.
 * Archiving drops its host records from the database: the original files, the reports, the flags and the
 * notes are kept, and taking it out of the archive reads the files again.
 */

const INPUT =
  'w-28 border border-line bg-canvas px-2 py-1 font-mono text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

export default function ArchivingSection() {
  const [held, setHeld] = useState(null) // what the server has: { enabled, days, defaults }
  const [enabled, setEnabled] = useState(false)
  const [days, setDays] = useState('180')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [saved, setSaved] = useState(false)

  const take = useCallback((doc) => {
    setHeld(doc)
    setEnabled(Boolean(doc.enabled))
    setDays(String(doc.days))
  }, [])
  useEffect(() => {
    let alive = true
    api
      .get('/settings/archive')
      .then((doc) => alive && take(doc))
      .catch((failure) => alive && setError(failure.message))
    return () => {
      alive = false
    }
  }, [take])

  const problem = daysProblem(days)
  const dirty = Boolean(held) && (enabled !== Boolean(held.enabled) || String(held.days) !== String(days).trim())

  const save = async (event) => {
    event?.preventDefault()
    if (problem) return false
    setBusy(true)
    setError(null)
    try {
      take(await api.put('/settings/archive', { enabled, days: Number(days) }))
      setSaved(true)
      return true
    } catch (failure) {
      setError(failure.message)
      return false
    } finally {
      setBusy(false)
    }
  }
  useUnsavedChanges(dirty, {
    what: 'The rule that archives closed incidents',
    save: problem ? undefined : save,
  })

  if (!held) return error ? <ErrorNote>{error}</ErrorNote> : <Wait>Loading the rule…</Wait>
  return (
    <form onSubmit={save} className="flex max-w-3xl flex-col gap-4">
      <p className="text-sm text-fg-muted">
        Archiving drops the host records of a closed incident from the database to free it. The original files, the
        reports, the flags and the notes are kept; the incident becomes read-only and leaves the lists, and taking it
        out of the archive reads its files again. One incident is archived by hand from its header, or from the list.
      </p>
      <div className="flex items-center gap-3">
        <Switch
          checked={enabled}
          onChange={(value) => {
            setSaved(false)
            setEnabled(value)
          }}
          label="Archive the incidents closed for long"
        />
        <span className="text-sm text-fg">Archive the incidents closed for long, by themselves</span>
      </div>
      <label className="flex flex-col gap-1 self-start" htmlFor="archive-days">
        <span className="text-xs font-medium text-fg-muted">Closed for more than (days)</span>
        <input
          id="archive-days"
          type="number"
          inputMode="numeric"
          min={DAYS_RANGE.min}
          max={DAYS_RANGE.max}
          value={days}
          disabled={!enabled}
          onChange={(event) => {
            setSaved(false)
            setDays(event.target.value)
          }}
          aria-invalid={Boolean(problem) || undefined}
          className={`${INPUT} disabled:opacity-50`}
        />
        {problem && <span className="text-xs text-high">{problem}</span>}
      </label>
      {error && <ErrorNote>{error}</ErrorNote>}
      <div className="flex items-center gap-3">
        <Button type="submit" icon={Save} waiting={busy} disabled={busy || !dirty || Boolean(problem)}>
          {busy ? 'Saving…' : 'Save'}
        </Button>
        {saved && !dirty && (
          <span role="status" className="text-sm text-fg-muted">
            Saved.
          </span>
        )}
        {held.defaults && (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => {
              setSaved(false)
              setEnabled(Boolean(held.defaults.enabled))
              setDays(String(held.defaults.days))
            }}
          >
            Back to the defaults
          </Button>
        )}
      </div>
    </form>
  )
}
