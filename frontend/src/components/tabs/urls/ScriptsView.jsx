import { useEffect, useMemo, useRef, useState } from 'react'
import { Download, FileCode2 } from 'lucide-react'
import { Badge, Button, EmptyState, MicroSkull, StatCard } from '../../ui/index.js'
import { IocValue } from '../../../context/IocLookupContext.jsx'
import { useToast } from '../../../context/ToastContext.jsx'
import { api, apiUrl } from '../../../services/api.js'
import { copyText } from '../../../lib/download.js'
import { formatBytes } from '../../../domain/events.js'
import {
  beautifySegments,
  codeSegments,
  looksMinified,
  scriptBadge,
  scriptName,
  scriptStats,
  sortScripts,
} from '../../../domain/urlscan.js'

/*
 * The scripts of a scanned page: those it loaded and those written in it,
 * each read as text (never run) and checked against Nik's signatures. The
 * list is sorted worst first; a script shows what was found, the indicators
 * in its code, and the code with what matched marked.
 */

const SEVERITY_COLOR = { high: 'red', medium: 'amber', low: 'slate' }

function Code({ code, findings, focus, beautified }) {
  const marks = useRef({})
  const segments = useMemo(() => {
    const parts = codeSegments(code, findings)
    return beautified ? beautifySegments(parts) : parts
  }, [code, findings, beautified])
  // The marks are other elements once the layout changes.
  useEffect(() => {
    marks.current = {}
  }, [segments])
  useEffect(() => {
    if (focus) marks.current[focus]?.scrollIntoView({ block: 'center' })
  }, [focus, segments])
  return (
    <pre
      aria-label="Script code"
      tabIndex={0}
      className="max-h-[28rem] overflow-auto whitespace-pre-wrap break-all border border-line bg-sunken p-2.5 font-mono text-[11px] leading-relaxed text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
    >
      {segments.map((part, index) =>
        part.finding ? (
          <mark
            key={index}
            ref={(node) => {
              if (node && !marks.current[part.finding]) marks.current[part.finding] = node
            }}
            title={part.finding}
            className={`text-high outline outline-1 ${part.finding === focus ? 'bg-high-soft outline-high' : 'bg-high-soft/60 outline-high-line'}`}
          >
            {part.text}
          </mark>
        ) : (
          <span key={index}>{part.text}</span>
        ),
      )}
    </pre>
  )
}

/** @param {{ scan: object }} props  the scan as GET /api/urls/{id} returns it */
export default function ScriptsView({ scan }) {
  const { showToast } = useToast()
  const scripts = useMemo(() => sortScripts(scan.result?.scripts ?? []), [scan.result])
  const stats = useMemo(() => scriptStats(scripts), [scripts])
  const [selected, setSelected] = useState(scripts[0]?.index ?? null)
  const [detail, setDetail] = useState(null)
  const [error, setError] = useState(null)
  const [focus, setFocus] = useState(null)
  // Laid out to be read when the script is minified; the analyst can switch.
  const [beautified, setBeautified] = useState(null)

  useEffect(() => {
    if (!scripts.some((script) => script.index === selected)) setSelected(scripts[0]?.index ?? null)
  }, [scripts, selected])

  useEffect(() => {
    if (selected === null) return undefined
    let cancelled = false
    setDetail(null)
    setError(null)
    setFocus(null)
    setBeautified(null)
    api
      .get(`/urls/${scan.id}/scripts/${selected}`)
      .then((doc) => !cancelled && setDetail(doc))
      .catch((err) => !cancelled && setError(err.message))
    return () => {
      cancelled = true
    }
  }, [scan.id, selected])

  if (scripts.length === 0)
    return (
      <EmptyState
        icon={FileCode2}
        title="No scripts"
        message="The page loaded and carried no script, or it was scanned before scripts were collected: re-scan it."
      />
    )
  const current = scripts.find((script) => script.index === selected)
  const pretty = beautified ?? (detail ? looksMinified(detail.code) : false)

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
        <StatCard label="Scripts" value={stats.total} />
        <StatCard label="Loaded / in the page" value={`${stats.external} / ${stats.inline}`} />
        <StatCard
          label="With findings"
          value={stats.flagged}
          tone={stats.high ? 'danger' : stats.flagged ? 'warn' : 'default'}
        />
        <StatCard label="Obfuscated" value={stats.obfuscated} tone={stats.obfuscated ? 'warn' : 'default'} />
        <StatCard label="Third-party hosts" value={stats.hosts} />
      </div>
      <p className="text-xs text-fg-muted">
        Read as text and matched against Nik&apos;s signatures: nothing is run. What the scripts do counts in the
        scan&apos;s score.
      </p>

      <div className="grid gap-3 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.4fr)]">
        <ul aria-label="Scripts" className="max-h-[40rem] overflow-y-auto border border-line bg-panel">
          {scripts.map((script) => {
            const badge = scriptBadge(script)
            const active = script.index === selected
            return (
              <li key={script.index} className="border-b border-line-soft last:border-b-0">
                <button
                  type="button"
                  onClick={() => setSelected(script.index)}
                  aria-current={active ? 'true' : undefined}
                  className={[
                    'w-full px-3 py-2 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent',
                    active ? 'bg-raised shadow-[inset_2px_0_0_var(--color-accent)]' : 'hover:bg-raised/60',
                  ].join(' ')}
                >
                  <span className="flex items-start justify-between gap-2">
                    <span className="min-w-0 break-all font-mono text-xs font-semibold text-fg">
                      {scriptName(script)}
                    </span>
                    <Badge color={badge.color}>{badge.label}</Badge>
                  </span>
                  <span className="mt-0.5 block truncate font-mono text-[11px] text-fg-muted">
                    {[
                      script.kind === 'inline' ? 'in the page' : script.host,
                      formatBytes(script.size),
                      script.thirdParty ? 'third party' : null,
                      script.obfuscation >= 25 ? `${script.obfuscation} % obfuscated` : null,
                    ]
                      .filter(Boolean)
                      .join(' · ')}
                  </span>
                </button>
              </li>
            )
          })}
        </ul>

        {current && (
          <section aria-label="Script" className="min-w-0 space-y-3">
            <div className="border border-line bg-panel">
              <header className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-3 py-1.5 font-mono text-[11px] uppercase tracking-wider text-fg-muted">
                <span>Findings · {current.findings.length}</span>
                <span className="normal-case">
                  sha256 <IocValue type="sha256" value={current.sha256} className="break-all" />
                </span>
              </header>
              <div className="space-y-2 px-3 py-2">
                {current.kind === 'external' && (
                  <p className="break-all font-mono text-xs">
                    <IocValue type="url" value={current.url} />
                  </p>
                )}
                {current.library && (
                  <p className="text-xs text-fg-muted">
                    Recognised as <b className="text-fg">{current.library}</b>.
                  </p>
                )}
                {current.findings.length === 0 ? (
                  <p className="text-sm text-fg-muted">No signature matches this script.</p>
                ) : (
                  <ul>
                    {current.findings.map((finding) => (
                      <li key={finding.id} className="border-b border-line-soft last:border-b-0">
                        <button
                          type="button"
                          onClick={() => setFocus(finding.id)}
                          title="Show in the code"
                          className="grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-baseline gap-2 py-1.5 text-left text-sm hover:bg-raised/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                        >
                          <Badge color={SEVERITY_COLOR[finding.severity]}>{finding.severity}</Badge>
                          <span className="min-w-0">
                            {finding.title}
                            <span className="block break-all font-mono text-[11px] text-fg-muted">
                              line {finding.line} · {finding.excerpt}
                            </span>
                          </span>
                          <span className="font-mono text-[11px] text-fg-subtle">{finding.id}</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
                {current.iocs.length > 0 && (
                  <p className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-xs">
                    <span className="font-sans text-fg-muted">Indicators in this script:</span>
                    {current.iocs.map((ioc) => (
                      <IocValue
                        key={`${ioc.type}:${ioc.value}`}
                        type={ioc.type}
                        value={ioc.value}
                        className="break-all"
                      />
                    ))}
                  </p>
                )}
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h4 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">
                  Code {current.truncated && <span className="normal-case">· first 300 000 characters</span>}
                </h4>
                <span className="flex flex-wrap items-center gap-2">
                  <label
                    className="flex items-center gap-1.5 text-xs text-fg-muted"
                    title="A line per statement, blocks indented. Only white space changes."
                  >
                    <input
                      type="checkbox"
                      checked={pretty}
                      disabled={!detail}
                      onChange={(event) => setBeautified(event.target.checked)}
                    />
                    Beautified
                  </label>
                  <Button
                    size="xs"
                    variant="secondary"
                    disabled={!detail}
                    onClick={async () =>
                      showToast({
                        message: (await copyText(detail.code)) ? 'Code copied.' : 'The browser refused to copy.',
                      })
                    }
                  >
                    Copy
                  </Button>
                  <a
                    href={apiUrl(`/urls/${scan.id}/scripts/${current.index}/download`)}
                    title="The script in a zip, password: infected"
                    className="inline-flex h-7 items-center gap-1 border border-line px-2 text-xs text-fg hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    <Download className="h-3.5 w-3.5" aria-hidden="true" /> Download (zip, infected)
                  </a>
                </span>
              </div>
              {error ? (
                <p role="alert" className="font-mono text-xs text-high">
                  {error}
                </p>
              ) : !detail ? (
                <MicroSkull className="text-lg text-fg-muted" />
              ) : (
                <Code code={detail.code} findings={detail.findings} focus={focus} beautified={pretty} />
              )}
            </div>
          </section>
        )}
      </div>
    </div>
  )
}
