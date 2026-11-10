import { useCallback, useEffect, useState } from 'react'
import { ExternalLink, Radar, RefreshCw } from 'lucide-react'
import { Badge, Button } from '../../ui/index.js'
import { api } from '../../../services/api.js'
import { LOOKUP_TYPES, verdictMeta } from '../../../utils/enrichment.js'
import { formatDateTime } from '../../../utils/time.js'

/*
 * The external reputation of one indicator (Where seen): the cached answer of
 * each provider, and "Check now". Values Nik never sends (private, internal,
 * allowlisted, TLP:RED) say why instead.
 */

export default function IocReputation({ type, value }) {
  const [state, setState] = useState({ loading: true })
  const [checking, setChecking] = useState(false)
  const [skipped, setSkipped] = useState([])

  const load = useCallback(() => {
    const query = new URLSearchParams({ type, value })
    api
      .get(`/enrichment?${query}`)
      .then((data) => setState({ loading: false, data }))
      .catch((err) => setState({ loading: false, error: err.message }))
  }, [type, value])

  useEffect(() => {
    setSkipped([])
    if (LOOKUP_TYPES.has(type)) load()
  }, [type, load])

  if (!LOOKUP_TYPES.has(type)) return null

  const check = async (force) => {
    setChecking(true)
    try {
      const res = await api.post('/enrichment/check', { type, value, force })
      setState({ loading: false, data: { ...state.data, results: res.results } })
      setSkipped(res.skipped ?? [])
    } catch (err) {
      setState((prev) => ({ ...prev, error: err.message }))
    } finally {
      setChecking(false)
    }
  }

  const data = state.data
  const results = data?.results ?? []
  const canCheck = data && !data.blocked && data.providers.length > 0

  return (
    <section aria-label="External reputation" className="space-y-2 border-t border-line pt-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-fg-muted">
          <Radar className="h-3.5 w-3.5" aria-hidden="true" />
          External reputation
        </h3>
        {canCheck && (
          <Button
            size="xs"
            variant="secondary"
            icon={RefreshCw}
            onClick={() => check(results.length > 0)}
            disabled={checking}
          >
            {checking ? 'Checking…' : results.length ? 'Check again' : 'Check now'}
          </Button>
        )}
      </div>
      {state.loading && <p className="font-mono text-xs text-fg-muted">Loading…</p>}
      {state.error && <p className="text-xs text-high">{state.error}</p>}
      {data?.blocked && <p className="text-xs text-fg-muted">Never sent outside: {data.blocked}.</p>}
      {data && !data.blocked && data.providers.length === 0 && (
        <p className="text-xs text-fg-muted">
          No provider is configured for this type (Settings → Threat intelligence).
        </p>
      )}
      {results.length > 0 && (
        <ul className="divide-y divide-line-soft border border-line">
          {results.map((r) => {
            const meta = verdictMeta(r.verdict)
            return (
              <li key={r.provider} className="grid gap-x-3 gap-y-0.5 px-3 py-2 sm:grid-cols-[11rem_minmax(0,1fr)_auto]">
                <span className="text-xs font-medium text-fg">{r.label}</span>
                <span className="min-w-0 text-xs">
                  {r.status === 'error' ? (
                    <span className="text-med">{r.error}</span>
                  ) : r.status === 'running' ? (
                    <span className="text-fg-muted">checking…</span>
                  ) : (
                    <>
                      <Badge color={meta.color}>{meta.label}</Badge>{' '}
                      <span className="break-words text-fg">{r.summary}</span>
                    </>
                  )}
                </span>
                <span className="flex items-center gap-2 whitespace-nowrap font-mono text-[11px] text-fg-subtle">
                  {formatDateTime(Date.parse(r.checkedAt))}
                  {r.link && (
                    <a
                      href={r.link}
                      target="_blank"
                      rel="noopener noreferrer"
                      aria-label={`Open on ${r.label}`}
                      className="text-link hover:text-link-fg"
                    >
                      <ExternalLink className="h-3.5 w-3.5" />
                    </a>
                  )}
                </span>
              </li>
            )
          })}
        </ul>
      )}
      {skipped.length > 0 && (
        <p className="text-xs text-fg-muted">
          Not asked now: {skipped.map((s) => `${s.label} (${s.reason})`).join(', ')}.
        </p>
      )}
      {data && !data.blocked && canCheck && results.length === 0 && !state.loading && (
        <p className="text-xs text-fg-muted">
          Not checked yet. “Check now” sends the value to {data.providers.length} provider(s).
        </p>
      )}
    </section>
  )
}
