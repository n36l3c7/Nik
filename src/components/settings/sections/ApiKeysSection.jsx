import { useCallback, useEffect, useState } from 'react'
import { AlertCircle, Check, Copy, KeyRound, Plus, Trash2 } from 'lucide-react'
import { api } from '../../../services/api.js'
import { useAudit } from '../../../context/AuditContext.jsx'
import { useAuth } from '../../../context/AuthContext.jsx'
import { formatRelative } from '../../../utils/time.js'
import { Badge, Button } from '../../ui/index.js'

/*
 * API keys settings section (admin only): create and revoke keys that let
 * external clients drive the platform via the REST API (see /api/docs). The
 * plaintext key is shown exactly once, right after creation.
 */

const INPUT_CLASS =
  'w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 ' +
  'placeholder:text-slate-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 ' +
  'dark:border-slate-800 dark:bg-slate-950 dark:text-white dark:placeholder:text-slate-500'

/** One-time reveal box for a freshly created key. */
function CreatedKey({ value, onDismiss }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    } catch {
      /* insecure context: ignore */
    }
  }
  return (
    <div className="space-y-2 rounded-lg border border-cyan-300 bg-cyan-50 p-3 dark:border-cyan-500/40 dark:bg-cyan-500/10">
      <p className="text-xs font-medium text-cyan-800 dark:text-cyan-300">
        Copy this key now — it is shown only once and cannot be retrieved again.
      </p>
      <div className="flex items-center gap-2">
        <code className="min-w-0 flex-1 truncate rounded bg-white px-2 py-1.5 font-mono text-xs text-slate-800 dark:bg-slate-950 dark:text-slate-100">
          {value}
        </code>
        <Button size="sm" variant="secondary" icon={copied ? Check : Copy} onClick={copy}>
          {copied ? 'Copied' : 'Copy'}
        </Button>
        <Button size="sm" variant="ghost" onClick={onDismiss}>
          Done
        </Button>
      </div>
    </div>
  )
}

export default function ApiKeysSection() {
  const { log } = useAudit()
  const { currentUser } = useAuth()

  const [keys, setKeys] = useState([])
  const [label, setLabel] = useState('')
  const [role, setRole] = useState('analyst')
  const [readOnly, setReadOnly] = useState(false)
  const [expiresDays, setExpiresDays] = useState('')
  const [created, setCreated] = useState(null) // plaintext key shown once
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  const reload = useCallback(async () => {
    try {
      const res = await api.get('/keys')
      setKeys(Array.isArray(res?.keys) ? res.keys : [])
    } catch (err) {
      setError(err.message)
    }
  }, [])

  useEffect(() => {
    reload()
  }, [reload])

  const handleCreate = async (event) => {
    event.preventDefault()
    const name = label.trim()
    if (!name || busy) return
    setBusy(true)
    setError(null)
    try {
      const payload = { label: name, role }
      // Admin keys always get full scopes; for analyst keys, offer read-only.
      if (role !== 'admin' && readOnly) payload.scopes = ['read']
      const days = Number(expiresDays)
      if (Number.isFinite(days) && days > 0) payload.expiresInDays = days
      const res = await api.post('/keys', payload)
      setCreated(res.key)
      setLabel('')
      setRole('analyst')
      setReadOnly(false)
      setExpiresDays('')
      await reload()
      log({ actor: currentUser?.username, action: 'apikey.create', details: `Created ${role} API key "${name}"` })
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const handleRevoke = async (key) => {
    setError(null)
    try {
      await api.del(`/keys/${key.id}`)
      await reload()
      log({ actor: currentUser?.username, action: 'apikey.revoke', details: `Revoked API key "${key.label}"` })
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <section className="space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <KeyRound className="h-5 w-5 text-cyan-600 dark:text-cyan-400" />
          <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">API keys</h2>
          <Badge color="slate">{keys.length}</Badge>
        </div>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Keys let external clients drive the platform via the REST API. Send the key in the{' '}
          <code className="font-mono">X-API-Key</code> header. A key grants analyst-level access
          (incidents, notes, uploads); it cannot manage users or keys. See the{' '}
          <a href="/api/docs" className="font-medium text-cyan-700 hover:underline dark:text-cyan-400">
            interactive API docs
          </a>
          .
        </p>
      </div>

      {error && (
        <div
          role="alert"
          className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/60 dark:text-red-400"
        >
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          <span>{error}</span>
        </div>
      )}

      {created && <CreatedKey value={created} onDismiss={() => setCreated(null)} />}

      {keys.length > 0 ? (
        <ul className="divide-y divide-slate-200 overflow-hidden rounded-lg border border-slate-200 dark:divide-slate-800 dark:border-slate-800">
          {keys.map((key) => (
            <li key={key.id} className="flex items-center justify-between gap-3 px-3 py-2.5">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="truncate text-sm font-medium text-slate-800 dark:text-slate-100">
                    {key.label}
                  </span>
                  <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-500 dark:bg-slate-800 dark:text-slate-400">
                    {key.prefix}…
                  </code>
                  <Badge color={key.role === 'admin' ? 'cyan' : 'slate'}>{key.role}</Badge>
                  {!(key.scopes || []).includes('write') && <Badge color="amber">read-only</Badge>}
                </div>
                <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                  Created {formatRelative(key.createdAt)}
                  {key.lastUsedAt ? ` · last used ${formatRelative(key.lastUsedAt)}` : ' · never used'}
                  {key.expiresAt ? ` · expires ${formatRelative(key.expiresAt)}` : ''}
                </p>
              </div>
              <Button
                variant="ghost"
                size="xs"
                icon={Trash2}
                onClick={() => handleRevoke(key)}
                title={`Revoke "${key.label}"`}
                aria-label={`Revoke ${key.label}`}
                className="text-slate-400 hover:text-red-600 dark:text-slate-500 dark:hover:text-red-400"
              />
            </li>
          ))}
        </ul>
      ) : (
        <p className="rounded-lg border border-dashed border-slate-300 px-3 py-6 text-center text-sm text-slate-500 dark:border-slate-700 dark:text-slate-400">
          No API keys yet. Create one below to use the REST API.
        </p>
      )}

      <form onSubmit={handleCreate} className="space-y-3 rounded-lg border border-dashed border-slate-300 p-3 dark:border-slate-700">
        <p className="text-xs font-medium text-slate-600 dark:text-slate-300">Create a key</p>
        <div className="flex flex-wrap items-end gap-2">
          <div className="min-w-[10rem] flex-1">
            <label htmlFor="new-key-label" className="mb-1 block text-xs font-medium text-slate-500 dark:text-slate-400">
              Label
            </label>
            <input
              id="new-key-label"
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. ingest-pipeline"
              className={INPUT_CLASS}
            />
          </div>
          <div>
            <label htmlFor="new-key-role" className="mb-1 block text-xs font-medium text-slate-500 dark:text-slate-400">
              Permissions
            </label>
            <select
              id="new-key-role"
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className={INPUT_CLASS}
            >
              <option value="analyst">Analyst (incidents, notes, uploads)</option>
              <option value="admin">Admin (also users &amp; backup)</option>
            </select>
          </div>
          <div>
            <label htmlFor="new-key-expiry" className="mb-1 block text-xs font-medium text-slate-500 dark:text-slate-400">
              Expires (days)
            </label>
            <input
              id="new-key-expiry"
              type="number"
              min="1"
              value={expiresDays}
              onChange={(e) => setExpiresDays(e.target.value)}
              placeholder="never"
              className={`${INPUT_CLASS} w-28`}
            />
          </div>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <label
            className={[
              'flex items-center gap-2 text-sm',
              role === 'admin' ? 'text-slate-400 dark:text-slate-600' : 'text-slate-600 dark:text-slate-300',
            ].join(' ')}
          >
            <input
              type="checkbox"
              checked={readOnly}
              disabled={role === 'admin'}
              onChange={(e) => setReadOnly(e.target.checked)}
              className="h-4 w-4 rounded border-slate-300 text-cyan-600 focus-visible:ring-2 focus-visible:ring-cyan-500 dark:border-slate-600 dark:bg-slate-800"
            />
            Read-only (no writes)
          </label>
          <Button type="submit" icon={Plus} disabled={busy || !label.trim()}>
            {busy ? 'Creating…' : 'Create key'}
          </Button>
        </div>
      </form>
    </section>
  )
}
