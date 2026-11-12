import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Boxes, Braces, Clock, Download, ExternalLink, Globe, Radar, RefreshCw, ShieldCheck } from 'lucide-react'
import { Badge, Button } from '../ui/index.js'
import SourceDetails from './SourceDetails.jsx'
import { api, apiUrl } from '../../services/api.js'
import { IOC_TYPES, sourceLabel } from '../../domain/iocs.js'
import {
  LOOKUP_TYPES,
  analysisActions,
  analysisColor,
  analysisLabel,
  countsLine,
  retentionLabel,
  verdictChanges,
  verdictMeta,
  verdictShares,
} from '../../domain/enrichment.js'
import { formatDateTime, formatRelative } from '../../lib/time.js'

/*
 * Everything Nik knows about one indicator, in two columns:
 *   left   the overall verdict (a score weighted by source), the sources to
 *          choose from, and "Seen in": every incident it appears in;
 *   right  the chosen source in full, as on the provider's own page, with
 *          its earlier verdicts and its answer as JSON (copy or download).
 * Answers past the retention of their type are asked again when the page
 * opens (Settings can turn that off); "Check again" asks at once.
 */

const SHARE_COLOUR = {
  malicious: 'bg-high-line',
  suspicious: 'bg-med-line',
  harmless: 'bg-accent',
  unknown: 'bg-fg-subtle',
}
const DOT = { malicious: 'bg-high-line', suspicious: 'bg-med-line', harmless: 'bg-accent', unknown: 'bg-fg-subtle' }
const SCORE_TONE = { malicious: 'text-high', suspicious: 'text-med', harmless: 'text-accent', unknown: 'text-fg' }

function Heading({ children }) {
  return <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">{children}</h3>
}

/** Days since the domain was registered, when the registry says it is a young one; else null. */
function youngDomainDays(results = []) {
  const found = results.find((result) => result.provider === 'registration' && result.data?.young)
  return found ? (found.data.ageDays ?? null) : null
}

function Verdict({ summary, retentionDays, lookedUp, young = null }) {
  if (!lookedUp)
    return (
      <div className="border border-line bg-panel px-3 py-2.5 text-xs text-fg-muted">
        E-mail addresses are never sent to external sources.
      </div>
    )
  if (!summary)
    return (
      <div className="border border-line bg-panel px-3 py-2.5">
        <p className="text-xs text-fg-muted">Reputation · what the sources say</p>
        <p className="font-mono text-lg font-extrabold text-fg">not checked</p>
        <p className="text-xs text-fg-muted">No source has answered about this value yet.</p>
      </div>
    )
  const meta = verdictMeta(summary.verdict)
  return (
    <div className="space-y-2 border border-line bg-panel px-3 py-2.5">
      <p className="text-xs text-fg-muted">Reputation · what the sources say</p>
      <p className="flex items-baseline gap-2 font-mono">
        <span className={`text-2xl font-extrabold tabular-nums ${SCORE_TONE[summary.verdict]}`}>{summary.score}</span>
        <span className="text-xs text-fg-muted">/ 100</span>
        <Badge color={meta.color}>{meta.label}</Badge>
      </p>
      <div
        role="img"
        aria-label={countsLine(summary.counts)}
        className="flex h-2 overflow-hidden bg-line-soft"
        title="How many sources gave each verdict"
      >
        {verdictShares(summary.counts).map((s) => (
          <span key={s.verdict} className={SHARE_COLOUR[s.verdict]} style={{ width: `${s.share}%` }} />
        ))}
      </div>
      <p className="text-xs text-fg-muted">{countsLine(summary.counts)}</p>
      {young !== null && (
        <p role="alert" className="border-l-2 border-high-line bg-high-soft/50 px-2.5 py-1.5 text-xs text-fg">
          <b>
            Domain registered {young} {young === 1 ? 'day' : 'days'} ago
          </b>
          : it counts in the score. See Registration below.
        </p>
      )}
      <p className="text-[11px] text-fg-subtle">
        The score weighs each source (shown as ×1 to ×3). Answers stand for {retentionLabel(retentionDays)}.
      </p>
    </div>
  )
}

function SeenIn({ lookup, activeIncidentId, onOpenIncident, onOpenArtifact }) {
  if (lookup.loading) return <p className="font-mono text-xs text-fg-muted">Searching every incident…</p>
  if (lookup.error) return <p className="text-xs text-high">{lookup.error}</p>
  const incidents = lookup.data?.incidents ?? []
  // Artifacts analysed on their own (no incident) that hold the value.
  const alone = lookup.data?.artifacts ?? []
  if (!incidents.length && !alone.length)
    return (
      <p className="text-xs text-fg-muted">
        Not in any saved incident or artifact yet (changes made in the last seconds are indexed when they are saved).
      </p>
    )
  return (
    <ul className="divide-y divide-line-soft border border-line">
      {alone.length > 0 && (
        <li className="space-y-1 px-3 py-2">
          <p className="text-sm font-medium text-fg">On their own, in no incident</p>
          <div className="flex flex-wrap gap-1">
            {alone.map((artifact) => (
              <button
                key={artifact.id}
                type="button"
                onClick={() => onOpenArtifact(artifact.id)}
                title="Open the artifact"
                className="inline-flex max-w-full items-center gap-1 border border-line px-1.5 font-mono text-[11px] text-link hover:border-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <Boxes className="h-3 w-3 shrink-0" aria-hidden="true" />
                <span className="truncate">
                  {artifact.kind}: {artifact.name}
                </span>
              </button>
            ))}
          </div>
        </li>
      )}
      {incidents.map((incident) => {
        const current = incident.id === activeIncidentId
        return (
          <li key={incident.id} className="space-y-1 px-3 py-2">
            <p className="flex flex-wrap items-center gap-2 text-sm font-medium text-fg">
              <span className="min-w-0 break-words">{incident.name || incident.id}</span>
              {current && <Badge color="emerald">this incident</Badge>}
              {!current && (
                <button
                  type="button"
                  onClick={() => onOpenIncident(incident.id)}
                  className="ml-auto inline-flex items-center gap-1 text-xs text-accent hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" /> Open
                </button>
              )}
            </p>
            <div className="flex flex-wrap gap-1">
              {incident.sources.map((source) =>
                incident.sourceArtifacts?.[source] ? (
                  // The source is an artifact of that incident: open its analysis.
                  <button
                    key={source}
                    type="button"
                    onClick={() => onOpenArtifact(incident.sourceArtifacts[source])}
                    title="Open the artifact this comes from"
                    className="inline-flex items-center gap-1 border border-line px-1.5 font-mono text-[11px] text-link hover:border-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    <Boxes className="h-3 w-3" aria-hidden="true" />
                    {sourceLabel(source)}
                  </button>
                ) : (
                  <Badge key={source} color="slate">
                    {sourceLabel(source)}
                  </Badge>
                ),
              )}
            </div>
            <p className="font-mono text-[11px] text-fg-muted">
              {incident.count}× ·{' '}
              {incident.firstSeen
                ? `${formatDateTime(incident.firstSeen)} → ${formatDateTime(incident.lastSeen)}`
                : 'no timestamp'}
            </p>
          </li>
        )
      })}
    </ul>
  )
}

/**
 * What Nik saw when it analysed the value itself: the scan of the address,
 * the file with that hash. Or, for an address not analysed yet, the offer to
 * visit it. Nothing is visited until the analyst clicks.
 */
function AnalysedByNik({ type, value, analysis, onAnalysis, onOpenArtifact }) {
  if (!analysis) return null
  const actions = analysisActions(type, value, analysis)
  const artifact = analysis.artifacts[0] ?? null
  if (!artifact && actions.length === 0) return null
  const run = (id) => onAnalysis(actions.find((action) => action.id === id))
  return (
    <section aria-label="Analysed by Nik" className="space-y-2 border border-line bg-panel px-3 py-2.5">
      <p className="text-xs text-fg-muted">Analysis · what Nik saw</p>
      {artifact ? (
        <>
          <p className="flex flex-wrap items-center gap-2 font-mono text-sm">
            <Badge color={analysisColor(artifact)}>{analysisLabel(artifact)}</Badge>
            <span className="text-[11px] text-fg-muted">
              {artifact.kind} · {formatRelative(artifact.scannedAt ?? artifact.createdAt)}
            </span>
          </p>
          {artifact.screenshot && (
            <img
              src={apiUrl(`/urls/${artifact.id.replace(/^url-/, '')}/screenshot`)}
              alt="The page as the isolated browser saw it"
              className="max-h-36 w-full border border-line object-cover object-top"
            />
          )}
          {artifact.findings?.length > 0 && (
            <ul className="list-disc space-y-0.5 pl-4 text-xs text-fg">
              {artifact.findings.map((finding) => (
                <li key={finding}>{finding}</li>
              ))}
            </ul>
          )}
          {artifact.kind === 'url' && artifact.scripts > 0 && (
            <p className="text-xs text-fg-muted">
              {artifact.scripts} scripts{artifact.scriptsFlagged ? `, ${artifact.scriptsFlagged} with findings` : ''}
            </p>
          )}
          {analysis.verdict && (
            <p className="text-[11px] text-fg-subtle">
              Counts in the reputation as {analysis.verdict} (×{analysis.weight}).
            </p>
          )}
          <div className="flex flex-wrap gap-2">
            <Button size="xs" icon={Boxes} onClick={() => onOpenArtifact(artifact.id)}>
              Open the analysis
            </Button>
            {actions.some((action) => action.id === 'rescan') && (
              <Button size="xs" variant="secondary" icon={RefreshCw} onClick={() => run('rescan')}>
                Scan again
              </Button>
            )}
          </div>
          {analysis.artifacts.length > 1 && (
            <p className="text-[11px] text-fg-muted">
              {analysis.artifacts.length - 1} more:{' '}
              {analysis.artifacts.slice(1).map((other) => (
                <button
                  key={other.id}
                  type="button"
                  onClick={() => onOpenArtifact(other.id)}
                  className="mr-2 text-link hover:underline"
                >
                  {other.name}
                </button>
              ))}
            </p>
          )}
        </>
      ) : (
        <>
          <p className="text-sm text-fg">Not analysed by Nik yet.</p>
          <p className="text-xs text-fg-muted">
            The isolated browser can visit it: it types and submits nothing. The site sees the visit.
          </p>
          <Button size="xs" icon={Globe} onClick={() => run('analyse')}>
            {actions[0].label}
          </Button>
        </>
      )}
    </section>
  )
}

function SourceCard({ result, type, value, onNotice }) {
  const meta = verdictMeta(result.verdict)
  const changes = verdictChanges(result.history)
  const rawPath = `/enrichment/raw?${new URLSearchParams({ type, value, provider: result.provider })}`
  const copyJson = async () => {
    try {
      const body = await api.get(rawPath)
      await navigator.clipboard.writeText(JSON.stringify(body, null, 2))
      onNotice(`${result.label}: JSON copied.`)
    } catch (err) {
      onNotice(`${result.label}: ${err.message || 'the browser refused to copy'}`)
    }
  }
  return (
    <article aria-label={result.label} className="min-w-0 border border-line bg-panel">
      <header className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-line px-3 py-2">
        <h3 className="text-sm font-semibold text-fg">{result.label}</h3>
        {result.status === 'done' && <Badge color={meta.color}>{meta.label}</Badge>}
        {result.status === 'error' && <Badge color="amber">no answer</Badge>}
        {result.status === 'running' && <Badge>checking…</Badge>}
        {result.expired && (
          <Badge color="amber" title="Older than the retention of this type">
            <Clock className="h-3 w-3" aria-hidden="true" /> expired
          </Badge>
        )}
        <span className="ml-auto flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] text-fg-muted">
          <span title="Checked">{formatDateTime(Date.parse(result.checkedAt))}</span>
          {result.hasRaw && (
            <>
              <button
                type="button"
                onClick={copyJson}
                className="inline-flex items-center gap-1 text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <Braces className="h-3 w-3" aria-hidden="true" /> Copy JSON
              </button>
              <a
                href={apiUrl(rawPath)}
                download
                className="inline-flex items-center gap-1 text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <Download className="h-3 w-3" aria-hidden="true" /> Download JSON
              </a>
            </>
          )}
          {result.link && (
            <a
              href={result.link}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              Open on {result.label} <ExternalLink className="h-3 w-3" aria-hidden="true" />
            </a>
          )}
        </span>
      </header>
      <div className="space-y-4 p-3">
        {result.status === 'error' ? (
          <p className="font-mono text-xs text-med">{result.error}</p>
        ) : result.status === 'running' ? (
          <p className="font-mono text-xs text-fg-muted">Waiting for the answer…</p>
        ) : (
          <>
            <p className="font-mono text-xs text-fg">{result.summary}</p>
            <SourceDetails provider={result.provider} data={result.data} />
          </>
        )}
        {changes.length > 1 && (
          <section className="space-y-1 border-t border-line-soft pt-3">
            <Heading>Over time</Heading>
            <ol className="flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[11px] text-fg-muted">
              {changes.map((entry, index) => (
                <li key={entry.checkedAt} className="inline-flex items-center gap-2">
                  {index > 0 && <span aria-hidden="true">→</span>}
                  <span title={entry.summary}>
                    <Badge color={verdictMeta(entry.verdict).color}>{verdictMeta(entry.verdict).label}</Badge>{' '}
                    {formatDateTime(Date.parse(entry.checkedAt))}
                  </span>
                </li>
              ))}
            </ol>
          </section>
        )}
      </div>
    </article>
  )
}

/**
 * @param {{ type: string, value: string, activeIncidentId: string | null,
 *   onOpenIncident: (id: string) => void, onAllowlist: () => void, onNotice: (text: string) => void,
 *   onAnalysis: (action: object) => void,      // an entry of analysisActions(): analyse, open, scan again
 *   onOpenArtifact: (id: string) => void }} props
 */
export default function IocDetail({
  type,
  value,
  activeIncidentId,
  onOpenIncident,
  onAllowlist,
  onNotice,
  onAnalysis = () => {},
  onOpenArtifact = () => {},
}) {
  const lookedUp = LOOKUP_TYPES.has(type)
  const [lookup, setLookup] = useState({ loading: true, data: null, error: null })
  const [intel, setIntel] = useState({ loading: lookedUp, data: null, error: null })
  const [checking, setChecking] = useState(false)
  const [skipped, setSkipped] = useState([])
  const [chosen, setChosen] = useState(null)
  const refreshed = useRef(false)

  // Where it was seen.
  useEffect(() => {
    const controller = new AbortController()
    setLookup({ loading: true, data: null, error: null })
    api
      .get(`/iocs/lookup?${new URLSearchParams({ type, value })}`, { signal: controller.signal })
      .then((data) => setLookup({ loading: false, data, error: null }))
      .catch((err) => {
        if (!controller.signal.aborted)
          setLookup({ loading: false, data: null, error: err?.message ?? 'Lookup failed.' })
      })
    return () => controller.abort()
  }, [type, value])

  const check = useCallback(
    async (force) => {
      setChecking(true)
      try {
        const data = await api.post('/enrichment/check', { type, value, force })
        setIntel({ loading: false, data, error: null })
        setSkipped(data.skipped ?? [])
      } catch (err) {
        setIntel((prev) => ({ ...prev, loading: false, error: err.message }))
      } finally {
        setChecking(false)
      }
    },
    [type, value],
  )

  // What the sources said; expired answers are asked again, once.
  useEffect(() => {
    refreshed.current = false
    setChosen(null)
    setSkipped([])
    if (!lookedUp) return undefined
    let cancelled = false
    setIntel({ loading: true, data: null, error: null })
    api
      .get(`/enrichment?${new URLSearchParams({ type, value })}`)
      .then((data) => {
        if (cancelled) return
        setIntel({ loading: false, data, error: null })
        if (data.refresh?.length && !refreshed.current) {
          refreshed.current = true
          check(false)
        }
      })
      .catch((err) => !cancelled && setIntel({ loading: false, data: null, error: err.message }))
    return () => {
      cancelled = true
    }
  }, [type, value, lookedUp, check])

  const data = intel.data
  const results = useMemo(() => data?.results ?? [], [data])
  const notAsked = data?.notAsked ?? []
  const canCheck = Boolean(data && !data.blocked && data.providers.length > 0)
  // The source shown: the analyst's choice, else the first that flags the value, else the first.
  const current =
    results.find((r) => r.provider === chosen) ??
    results.find((r) => ['malicious', 'suspicious'].includes(r.verdict) && r.status === 'done') ??
    results[0] ??
    null
  const meta = IOC_TYPES[type] ?? { label: type }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <Badge color={meta.color}>{meta.label}</Badge>
          <code className="break-all font-mono text-lg font-extrabold text-fg">{value}</code>
          {(lookup.data?.allowlisted || data?.blocked) && (
            <Badge color="slate" title={data?.blocked ? `Never sent outside: ${data.blocked}` : 'On the IOC allowlist'}>
              <ShieldCheck className="h-3 w-3" aria-hidden="true" />{' '}
              {lookup.data?.allowlisted ? 'allowlisted' : 'never sent outside'}
            </Badge>
          )}
        </div>
        <div className="flex flex-wrap gap-2">
          {!lookup.data?.allowlisted && (
            <Button size="xs" variant="secondary" icon={ShieldCheck} onClick={onAllowlist}>
              Add to the allowlist…
            </Button>
          )}
          {canCheck && (
            <Button size="xs" icon={RefreshCw} onClick={() => check(results.length > 0)} disabled={checking}>
              {checking ? 'Checking…' : results.length ? 'Check again' : 'Check now'}
            </Button>
          )}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,19rem)_minmax(0,1fr)]">
        <div className="min-w-0 space-y-4">
          <Verdict
            summary={data?.summary}
            retentionDays={data?.retentionDays ?? 30}
            lookedUp={lookedUp}
            young={youngDomainDays(data?.results)}
          />

          <AnalysedByNik
            type={type}
            value={value}
            analysis={data?.analysis}
            onAnalysis={onAnalysis}
            onOpenArtifact={onOpenArtifact}
          />

          {lookedUp && (
            <section aria-label="Sources" className="space-y-1.5">
              <Heading>Sources</Heading>
              {intel.loading && <p className="font-mono text-xs text-fg-muted">Loading…</p>}
              {intel.error && <p className="text-xs text-high">{intel.error}</p>}
              {data?.blocked && <p className="text-xs text-fg-muted">Never sent outside: {data.blocked}.</p>}
              {data && !data.blocked && data.providers.length === 0 && results.length === 0 && (
                <p className="text-xs text-fg-muted">
                  No source is configured for this type (Settings → Threat intelligence).
                </p>
              )}
              {(results.length > 0 || notAsked.length > 0 || data?.analysis?.verdict) && (
                <ul className="border border-line bg-panel">
                  {results.map((r) => {
                    const m = verdictMeta(r.verdict)
                    const active = current?.provider === r.provider
                    return (
                      <li key={r.provider}>
                        <button
                          type="button"
                          onClick={() => setChosen(r.provider)}
                          aria-current={active ? 'true' : undefined}
                          className={[
                            'flex w-full items-center gap-2 border-l-2 px-2.5 py-1.5 text-left text-sm',
                            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent',
                            active ? 'border-l-accent bg-raised' : 'border-l-transparent hover:bg-raised',
                          ].join(' ')}
                        >
                          <span
                            className={`h-2 w-2 shrink-0 rounded-full ${r.status === 'done' ? DOT[r.verdict] : 'bg-med-line'}`}
                            aria-hidden="true"
                          />
                          <span className="min-w-0 flex-1 truncate text-fg">{r.label}</span>
                          <span className="font-mono text-[11px] text-fg-subtle" title="Weight in the score">
                            ×{r.weight}
                          </span>
                          {r.status === 'done' ? (
                            <Badge color={m.color}>{m.label}</Badge>
                          ) : (
                            <Badge color="amber">{r.status === 'running' ? 'checking' : 'no answer'}</Badge>
                          )}
                        </button>
                      </li>
                    )
                  })}
                  {data?.analysis?.verdict && (
                    // Nik's own analysis is one of the sources, with the highest weight.
                    <li className="flex items-center gap-2 border-l-2 border-l-transparent px-2.5 py-1.5 text-sm">
                      <span
                        className={`h-2 w-2 shrink-0 rounded-full ${DOT[data.analysis.verdict]}`}
                        aria-hidden="true"
                      />
                      <span className="min-w-0 flex-1 truncate">{data.analysis.label}</span>
                      <span className="font-mono text-[11px] text-fg-subtle">×{data.analysis.weight}</span>
                      <Badge color={verdictMeta(data.analysis.verdict).color}>{data.analysis.verdict}</Badge>
                    </li>
                  )}
                  {notAsked.map((p) => (
                    <li key={p.provider} className="flex items-center gap-2 px-2.5 py-1.5 text-sm text-fg-muted">
                      <span className="h-2 w-2 shrink-0 rounded-full border border-fg-subtle" aria-hidden="true" />
                      <span className="min-w-0 flex-1 truncate">{p.label}</span>
                      <span className="font-mono text-[11px] text-fg-subtle">not asked</span>
                    </li>
                  ))}
                </ul>
              )}
              {canCheck && results.length === 0 && !intel.loading && (
                <p className="text-xs text-fg-muted">
                  Not checked yet. “Check now” sends the value to {data.providers.length} source
                  {data.providers.length === 1 ? '' : 's'}.
                </p>
              )}
              {skipped.length > 0 && (
                <p className="text-xs text-fg-muted">
                  Not asked now: {skipped.map((s) => `${s.label} (${s.reason})`).join(', ')}.
                </p>
              )}
            </section>
          )}

          <section aria-label="Seen in" className="space-y-1.5">
            <Heading>
              Seen in
              {lookup.data
                ? ` · ${lookup.data.incidents.length} incident${lookup.data.incidents.length === 1 ? '' : 's'}${
                    lookup.data.artifacts?.length ? `, ${lookup.data.artifacts.length} on their own` : ''
                  }`
                : ''}
            </Heading>
            <SeenIn
              lookup={lookup}
              activeIncidentId={activeIncidentId}
              onOpenIncident={onOpenIncident}
              onOpenArtifact={onOpenArtifact}
            />
          </section>
        </div>

        <div className="min-w-0">
          {current ? (
            <SourceCard result={current} type={type} value={value} onNotice={onNotice} />
          ) : (
            <div className="flex h-full min-h-40 flex-col items-center justify-center gap-2 border border-dashed border-line p-6 text-center">
              <Radar className="h-6 w-6 text-fg-subtle" aria-hidden="true" />
              <p className="max-w-sm text-xs text-fg-muted">
                {!lookedUp
                  ? 'This type is not looked up on external sources.'
                  : data?.blocked
                    ? 'This value stays inside Nik.'
                    : 'What each source says about this value appears here once it has been checked.'}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
