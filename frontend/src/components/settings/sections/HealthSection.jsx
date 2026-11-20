import { useCallback, useEffect, useRef, useState } from 'react'
import { Activity, Copy, KeyRound, RefreshCw, Trash2 } from 'lucide-react'
import { api } from '../../../services/api.js'
import {
  groupRows,
  needingAttention,
  scrapeConfig,
  stateBadge,
  summary,
  thresholdsBody,
  thresholdsForm,
  thresholdsProblem,
} from '../../../domain/health.js'
import { safeLink } from '../../../domain/timers.js'
import { useToast } from '../../../context/ToastContext.jsx'
import { setPath } from '../../../lib/location.js'
import { useUnsavedChanges } from '../../../lib/unsaved.js'
import { formatDateTime, formatRelative } from '../../../lib/time.js'
import { usePageMenu } from '../../menu/usePageMenu.js'
import { Badge, Button, EmptyState, Modal, Wait } from '../../ui/index.js'

/*
 * System → Health (admins): whether the server is well, in one place.
 *
 * Each row is one thing an operator would otherwise go and look at: a value,
 * a state (fine, attention, problem), since when, and what to do. The pages
 * of Workers, Storage, Backup and the audit log are not repeated: a row sums
 * one up and leads to it. The server looks by itself once a minute and tells
 * every administrator when a row gets worse and when it is fine again; those
 * notices lead here.
 *
 * Under the rows: the thresholds, and the token a Prometheus presents to read
 * the same numbers at /api/metrics.
 */

const INPUT =
  'border border-line bg-canvas px-2 py-1 font-mono text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

function Row({ row }) {
  const badge = stateBadge(row.state)
  const link = safeLink(row.link)
  return (
    <li className="flex items-start justify-between gap-3 px-3 py-2">
      <div className="min-w-0">
        <p className="text-sm text-fg">
          {row.label}
          <span className="text-fg-muted"> · {row.value}</span>
        </p>
        {row.detail && <p className="mt-0.5 max-w-prose text-xs text-fg-muted">{row.detail}</p>}
        <p className="mt-0.5 text-xs text-fg-subtle">
          {row.since && row.state !== 'fine' ? `Since ${formatDateTime(Date.parse(row.since))}. ` : ''}
          {link && (
            <button
              type="button"
              onClick={() => setPath(link)}
              aria-label={`Open the page of ${row.label}`}
              className="text-accent-fg underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              Open its page
            </button>
          )}
        </p>
      </div>
      <Badge color={badge.color}>{badge.text}</Badge>
    </li>
  )
}

function Thresholds({ thresholds, onSaved }) {
  const [form, setForm] = useState(() => thresholdsForm(thresholds))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const loaded = JSON.stringify(thresholdsForm(thresholds))
  const dirty = JSON.stringify(form) !== loaded
  const problem = thresholdsProblem(form, thresholds)

  // Saved elsewhere while this page was open: an untouched form follows the server.
  const before = useRef(loaded)
  useEffect(() => {
    if (before.current !== loaded) {
      const was = before.current
      before.current = loaded
      setForm((current) => (JSON.stringify(current) === was ? thresholdsForm(thresholds) : current))
    }
  }, [loaded, thresholds])

  const save = async (event) => {
    event?.preventDefault()
    if (problem) return false
    setBusy(true)
    setError(null)
    try {
      const saved = await api.put('/health/thresholds', thresholdsBody(form, thresholds))
      before.current = JSON.stringify(thresholdsForm(saved.thresholds))
      setForm(thresholdsForm(saved.thresholds))
      onSaved(saved)
      return true
    } catch (failure) {
      setError(failure.message)
      return false
    } finally {
      setBusy(false)
    }
  }
  const unsaved = useUnsavedChanges(dirty, {
    what: 'The thresholds of the health page',
    save: problem ? undefined : () => save(),
  })

  return (
    <form onSubmit={save} aria-label="Thresholds" className="flex flex-col gap-3 border border-line bg-panel p-4">
      <h3 className="text-sm font-semibold text-fg">Thresholds</h3>
      <p className="max-w-prose text-xs text-fg-muted">
        From which value a row needs attention, and from which it is a problem. The administrators are told when a row
        passes one, and when it is fine again.
      </p>
      <ul className="grid gap-x-6 gap-y-2 md:grid-cols-2">
        {thresholds.map((entry) => (
          <li key={entry.name}>
            <label className="flex items-center justify-between gap-3 text-sm text-fg-muted">
              <span>{entry.label}</span>
              <input
                type="text"
                inputMode="numeric"
                aria-label={entry.label}
                value={form[entry.name] ?? ''}
                onChange={(event) => setForm((current) => ({ ...current, [entry.name]: event.target.value }))}
                className={`${INPUT} w-20 shrink-0 text-right`}
              />
            </label>
          </li>
        ))}
      </ul>
      {error && (
        <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high">
          {error}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" waiting={busy} disabled={busy || !dirty || Boolean(problem)} title={problem ?? undefined}>
          Save the thresholds
        </Button>
        {dirty && (
          <Button
            variant="secondary"
            disabled={busy}
            onClick={() => unsaved.leave(() => setForm(thresholdsForm(thresholds)))}
          >
            Discard
          </Button>
        )}
        {dirty && problem && <p className="text-xs text-med-fg">{problem}</p>}
      </div>
    </form>
  )
}

function Metrics({ token, onChanged }) {
  const { showToast } = useToast()
  const [busy, setBusy] = useState(false)
  const [made, setMade] = useState(null)
  const [error, setError] = useState(null)
  const config = scrapeConfig(typeof window === 'undefined' ? '' : window.location.origin)

  const copy = async (text, what) => {
    try {
      await navigator.clipboard.writeText(text)
      showToast({ message: `${what} copied.` })
    } catch {
      showToast({ message: 'The browser refused to copy.' })
    }
  }
  const make = async () => {
    setBusy(true)
    setError(null)
    try {
      const answer = await api.post('/health/metrics-token')
      setMade(answer.token)
      onChanged(answer.metricsToken)
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }
  const remove = async () => {
    setBusy(true)
    setError(null)
    try {
      onChanged((await api.del('/health/metrics-token')).metricsToken)
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section aria-label="Metrics for Prometheus" className="flex flex-col gap-3 border border-line bg-panel p-4">
      <h3 className="text-sm font-semibold text-fg">Metrics for Prometheus</h3>
      <p className="max-w-prose text-xs text-fg-muted">
        Every number of this page is at <span className="font-mono">/api/metrics</span>, in the format Prometheus reads,
        for whoever presents the scrape token and nobody else: not a signed-in person, not an API key. The token is
        shown once, when it is made.
      </p>
      <p role="status" aria-label="Scrape token" className="text-sm text-fg">
        {token.set
          ? `A token is set (it ends in ${token.ending}), made by ${token.createdBy || 'an administrator'} on ${formatDateTime(Date.parse(token.createdAt))}.`
          : token.environment
            ? 'No token was made here: the one of METRICS_TOKEN in the environment of the server is accepted.'
            : 'No token is set: the metrics answer to nobody.'}
      </p>
      {error && (
        <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high">
          {error}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="secondary" size="sm" icon={KeyRound} waiting={busy} disabled={busy} onClick={make}>
          {token.set ? 'Replace the token…' : 'Make a token…'}
        </Button>
        {token.set && (
          <Button variant="ghost" size="sm" icon={Trash2} disabled={busy} onClick={remove}>
            Remove the token
          </Button>
        )}
      </div>
      <details className="text-sm text-fg-muted">
        <summary className="cursor-pointer select-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent">
          How to point Prometheus at it
        </summary>
        <p className="mt-2 max-w-prose text-xs">
          The metrics are reached through the web address of Nik, like everything else. Put the token in a file only
          Prometheus reads, and add this job to its configuration:
        </p>
        <pre className="mt-2 overflow-x-auto border border-line bg-canvas p-3 font-mono text-xs text-fg">{config}</pre>
        <Button variant="ghost" size="sm" icon={Copy} className="mt-1" onClick={() => copy(config, 'The scrape job')}>
          Copy the job
        </Button>
      </details>

      <Modal
        open={made !== null}
        onClose={() => setMade(null)}
        title="Scrape token"
        footer={<Button onClick={() => setMade(null)}>I copied it</Button>}
      >
        <div className="flex flex-col gap-3 text-sm text-fg">
          <p>
            This is the only time the token is shown. Copy it now: the server keeps a hash of it and cannot show it
            again.
          </p>
          <p aria-label="The token" className="break-all border border-line bg-canvas p-3 font-mono text-xs">
            {made}
          </p>
          <div>
            <Button variant="secondary" size="sm" icon={Copy} onClick={() => copy(made, 'The token')}>
              Copy the token
            </Button>
          </div>
        </div>
      </Modal>
    </section>
  )
}

export default function HealthSection() {
  const [found, setFound] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setFound(await api.get('/health/details'))
      setError(null)
    } catch (failure) {
      setError(failure.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const pageMenu = usePageMenu(() => [
    {
      label: 'Refresh',
      icon: RefreshCw,
      disabled: loading,
      title: loading ? 'The health of the server is being read' : undefined,
      onSelect: load,
    },
  ])

  const rows = found?.rows ?? []
  const wrong = needingAttention(rows)

  return (
    <section className="space-y-6" onContextMenu={pageMenu}>
      <div>
        <div className="flex items-center gap-2">
          <Activity className="h-5 w-5 text-accent" aria-hidden="true" />
          <h2 className="text-base font-semibold text-fg">Health</h2>
        </div>
        <p className="mt-1 max-w-prose text-sm text-fg-muted">
          Whether the server is well: its disks, its queues, its workers, its backups, its database, its certificate and
          its audit log. The server looks once a minute and tells every administrator when something gets worse, and
          when it is fine again.
        </p>
      </div>

      {error && (
        <p role="alert" className="max-w-xl border border-high-line bg-high-soft px-3 py-2 text-sm text-high">
          {error}
        </p>
      )}
      {!found && !error && <Wait>Reading the health of the server…</Wait>}

      {found && (
        <div className="max-w-4xl space-y-5">
          <div className="flex items-center justify-between gap-3">
            <p role="status" aria-label="Summary" className="text-sm text-fg">
              {summary(found.counts)}{' '}
              <span className="text-fg-muted">
                {found.watchedAt ? `The server last looked ${formatRelative(found.watchedAt)}.` : ''}
              </span>
            </p>
            <Button variant="secondary" size="sm" icon={RefreshCw} waiting={loading} disabled={loading} onClick={load}>
              Refresh
            </Button>
          </div>

          {wrong.length > 0 && (
            <ul aria-label="What needs attention" className="divide-y divide-line border border-high-line bg-panel">
              {wrong.map((row) => (
                <Row key={row.id} row={row} />
              ))}
            </ul>
          )}

          {rows.length === 0 && (
            <EmptyState skull title="Nothing was measured" message="The server gave no row: read its log." />
          )}
          {groupRows(rows).map((group) => (
            <div key={group.name}>
              <h3 className="mb-1 font-mono text-[11px] uppercase tracking-wider text-fg-muted">{group.name}</h3>
              <ul aria-label={group.name} className="divide-y divide-line border border-line bg-panel">
                {group.rows.map((row) => (
                  <Row key={row.id} row={row} />
                ))}
              </ul>
            </div>
          ))}

          <Thresholds thresholds={found.thresholds} onSaved={(saved) => setFound(saved)} />
          <Metrics
            token={found.metricsToken}
            onChanged={(metricsToken) => setFound((current) => ({ ...current, metricsToken }))}
          />
        </div>
      )}
    </section>
  )
}
