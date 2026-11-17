import { useCallback, useEffect, useId, useState } from 'react'
import { ExternalLink } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { useSettings } from '../../context/SettingsContext.jsx'
import { setPath } from '../../lib/location.js'
import { api } from '../../services/api.js'
import { choosable, countText, listPath } from '../../domain/lists.js'

/*
 * Which list a feature reads. What Nik kept as a fixed list in a setting is
 * a list now (Settings → Lists): a section shows which one it reads, lets
 * whoever manages lists choose another of the same kind, and links to the
 * list itself, where its items are edited.
 */

/**
 * @param {{
 *   setting: string,          // the key of the feature: 'iocAllowlist', 'mail.orgDomains', 'state.hosts'…
 *   label: string,            // what the list is for: "Allowlist"
 *   hint?: string,
 * }} props
 */
export default function ListPicker({ setting, label, hint = null }) {
  const { can } = useAuth()
  const { reload } = useSettings()
  const id = useId()
  const [found, setFound] = useState(null)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    try {
      setFound(await api.get('/lists'))
      setError(null)
    } catch (failure) {
      setError(failure.message)
    }
  }, [])
  useEffect(() => {
    load()
  }, [load])

  const pointer = found?.pointers?.[setting] ?? null
  const options = choosable(found?.lists, pointer)
  const chosen = found?.lists.find((list) => list.name === pointer?.list) ?? null

  const choose = async (name) => {
    setError(null)
    try {
      await api.put('/lists/pointers', { pointers: { [setting]: name } })
      await Promise.all([load(), reload()])
    } catch (failure) {
      setError(failure.message)
    }
  }

  return (
    <div className="flex flex-col gap-1 border border-line bg-raised px-3 py-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <label htmlFor={id} className="text-xs font-medium text-fg-muted">
          {label}: reads the list
        </label>
        <select
          id={id}
          value={pointer?.list ?? ''}
          disabled={!pointer || !can('lists.manage') || options.length < 2}
          onChange={(event) => choose(event.target.value)}
          className="cursor-pointer border border-line bg-canvas px-2 py-1 text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-default disabled:opacity-80"
        >
          {!pointer && <option value="">…</option>}
          {options.map((list) => (
            <option key={list.name} value={list.name}>
              {list.label} ({list.name})
            </option>
          ))}
        </select>
        {chosen && <span className="font-mono text-xs text-fg-muted">{countText(chosen)}</span>}
        {pointer && can('lists.manage') && (
          <button
            type="button"
            onClick={() => setPath(listPath(pointer.list))}
            className="flex items-center gap-1 text-sm text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
            Open in Lists
          </button>
        )}
      </div>
      {hint && <p className="text-xs text-fg-subtle">{hint}</p>}
      {error && (
        <p role="alert" className="text-xs text-high-fg">
          {error}
        </p>
      )}
    </div>
  )
}
