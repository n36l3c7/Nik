import { useCallback, useEffect, useState } from 'react'
import {
  Boxes,
  ExternalLink,
  Flag,
  Globe,
  Link2,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  RefreshCw,
  Search,
  Trash2,
} from 'lucide-react'
import { AsciiSkull, Badge, Button, Card, EmptyState, MicroSkull } from '../../ui/index.js'
import { useArtifacts } from '../../../context/ArtifactContext.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { IocValue } from '../../../context/IocLookupContext.jsx'
import { useToast } from '../../../context/ToastContext.jsx'
import { api } from '../../../services/api.js'
import { displayUrl, isScanning, scanBadge, scanFlaggable, urlFromText } from '../../../domain/urlscan.js'
import { useItemMenu } from '../../menu/useRowMenu.js'
import { formatDateTime, anyToMs } from '../../../lib/time.js'
import { useStoredBoolean } from '../../../lib/useStoredBoolean.js'
import RemoteBrowser from '../mail/RemoteBrowser.jsx'
import RequestLog from '../network/RequestLog.jsx'

/*
 * ============================================================================
 * URL ANALYSIS — addresses visited by the isolated browser
 * ============================================================================
 *
 * The incident keeps a light reference per scanned address
 * (data.urls.scans); the result is fetched per address from
 * GET /api/urls/{id}: screenshot, final address, the navigations that led
 * there, the page's forms and the findings behind the verdict. Nothing is
 * typed or submitted during a scan; "Open in the isolated browser" lets the
 * analyst look by hand.
 *
 * Also shows one address on its own (ArtifactPage): `incident.standalone`.
 */

const POLL_MS = 2500
const NO_SCANS = []
const SEVERITY_COLOR = { high: 'red', medium: 'amber', low: 'slate' }
const INPUT =
  'h-9 min-w-0 flex-1 border border-line bg-canvas px-3 font-mono text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

function Facts({ rows }) {
  return (
    <dl className="grid grid-cols-[110px_minmax(0,1fr)] gap-x-3 gap-y-1.5 font-mono text-xs">
      {rows
        .filter(([, value]) => value)
        .map(([label, value]) => (
          <div key={label} className="contents">
            <dt className="text-fg-muted">{label}</dt>
            <dd className="min-w-0 break-all text-fg">{value}</dd>
          </div>
        ))}
    </dl>
  )
}

function Heading({ children }) {
  return <h3 className="mb-2 font-mono text-[11px] tracking-wider text-fg-muted">{children}</h3>
}

function Overview({ scan, incident }) {
  const menu = useItemMenu(incident)
  const result = scan.result ?? {}
  const certificate = result.certificate
  const issued = certificate?.validFrom ? formatDateTime(certificate.validFrom * 1000) : null
  return (
    <div className="grid gap-6 xl:grid-cols-[minmax(0,460px)_minmax(0,1fr)]">
      <div className="space-y-3">
        {result.screenshot ? (
          <img
            src={`/api/urls/${scan.id}/screenshot?at=${encodeURIComponent(scan.scannedAt ?? '')}`}
            alt={`Screenshot of ${displayUrl(result.finalUrl ?? scan.url)}`}
            className="w-full border border-line"
          />
        ) : (
          <p className="border border-line p-6 text-center text-sm text-fg-muted">No screenshot.</p>
        )}
        <p className="text-xs text-fg-muted">Taken by the isolated browser: nothing was typed, clicked or submitted.</p>
        <Facts
          rows={[
            ['final URL', result.finalUrl && <IocValue type="url" value={result.finalUrl} />],
            ['title', result.title],
            ['server', result.serverIp && <IocValue type="ip" value={result.serverIp} />],
            [
              'certificate',
              certificate && [certificate.issuer, issued && `issued ${issued}`].filter(Boolean).join(' · '),
            ],
            ['requests', `${result.requests ?? 0} · ${result.held ?? 0} held · ${result.blocked ?? 0} refused`],
            ['scanned', `${formatDateTime(anyToMs(scan.scannedAt))} · ${scan.createdBy}`],
          ]}
        />
      </div>

      <div className="min-w-0 space-y-5">
        <section>
          <Heading>WHY THIS VERDICT</Heading>
          {result.findings?.length ? (
            <ul className="space-y-1.5">
              {result.findings.map((finding) => (
                <li
                  key={`${finding.id}:${finding.text}`}
                  onContextMenu={(event) =>
                    menu(event, {
                      title: finding.text,
                      text: `${finding.points ? `+${finding.points} ` : ''}${finding.severity}: ${finding.text}`,
                    })
                  }
                  className="grid grid-cols-[40px_70px_minmax(0,1fr)] items-baseline gap-2 font-mono text-xs"
                >
                  <span className="text-right text-fg-muted">{finding.points ? `+${finding.points}` : ''}</span>
                  <Badge color={SEVERITY_COLOR[finding.severity] ?? 'slate'}>{finding.severity}</Badge>
                  <span className="break-words text-fg">{finding.text}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-fg-muted">Nothing suspicious was found on this page.</p>
          )}
        </section>

        <section>
          <Heading>HOW THE BROWSER GOT THERE</Heading>
          <ol className="space-y-1 font-mono text-xs">
            {(result.chain ?? []).map((step, index) => (
              <li key={`${index}:${step.url}`} className="flex gap-2">
                <span className="w-10 shrink-0 text-right text-fg-muted">{step.status ?? step.state ?? '—'}</span>
                <IocValue type="url" value={step.url} className="min-w-0 break-all text-left text-fg" />
              </li>
            ))}
            {!result.chain?.length && <li className="text-fg-muted">No navigation was recorded.</li>}
          </ol>
        </section>

        {result.forms?.length > 0 && (
          <section>
            <Heading>FORMS ON THE PAGE</Heading>
            <ul className="space-y-1 font-mono text-xs">
              {result.forms.map((form, index) => (
                <li key={`${index}:${form.action}`} className="flex flex-wrap items-baseline gap-2">
                  <span className="uppercase text-fg-muted">{form.method}</span>
                  <IocValue type="url" value={form.action} className="min-w-0 break-all text-left text-fg" />
                  {form.password && <Badge color="red">asks for a password</Badge>}
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </div>
  )
}

function Requests({ captureId }) {
  const [entries, setEntries] = useState(null)
  const [error, setError] = useState(null)
  useEffect(() => {
    let cancelled = false
    api
      .get(`/captures/${captureId}/requests`)
      .then((res) => !cancelled && setEntries(res.entries ?? []))
      .catch((err) => !cancelled && setError(err.message))
    return () => {
      cancelled = true
    }
  }, [captureId])
  const loadEntry = useCallback((id) => api.get(`/captures/${captureId}/requests/${id}`), [captureId])
  if (error) return <p className="font-mono text-xs text-high">{error}</p>
  if (!entries) return <MicroSkull className="text-lg text-fg-muted" />
  return <RequestLog entries={entries} loadEntry={loadEntry} />
}

function UrlDetail({ scan, incident, error, onRescan, onRemove, onBrowse, busy }) {
  const [view, setView] = useState('overview')
  const { openArtifact } = useArtifacts()
  const badge = scanBadge(scan)
  const scanning = isScanning(scan)
  return (
    <Card
      title={
        <span className="flex min-w-0 flex-wrap items-center gap-2">
          <span className="truncate">{displayUrl(scan.url)}</span>
          <Badge color={badge.color}>{badge.label}</Badge>
        </span>
      }
      icon={Link2}
      actions={
        <>
          <Button variant="ghost" size="xs" icon={RefreshCw} onClick={onRescan} disabled={busy || scanning}>
            {scanning ? 'Scanning…' : 'Re-scan'}
          </Button>
          <Button variant="secondary" size="xs" icon={Globe} onClick={onBrowse}>
            Open in the isolated browser
          </Button>
          {onRemove && (
            <Button
              variant="ghost"
              size="xs"
              icon={Trash2}
              onClick={onRemove}
              disabled={busy}
              title="Remove the address from this incident (it stays as an artifact)"
            >
              Remove
            </Button>
          )}
        </>
      }
    >
      {error ? (
        <p role="alert" className="font-mono text-sm text-high">
          {error}
        </p>
      ) : scanning ? (
        <div aria-busy="true" className="flex flex-col items-center gap-3 py-10">
          <AsciiSkull preset="medium" />
          <p role="status" className="font-mono text-sm text-fg-muted">
            The isolated browser is visiting {displayUrl(scan.url)}…
          </p>
        </div>
      ) : scan.status === 'error' ? (
        <div className="space-y-2 py-4">
          <p className="font-mono text-sm text-med-fg">The address was not visited.</p>
          <p className="text-sm text-fg-muted">{scan.error}</p>
        </div>
      ) : scan.result ? (
        <div className="space-y-4">
          <div role="tablist" className="flex gap-5 border-b border-line">
            {[
              ['overview', 'Overview'],
              ...(scan.captureId ? [['requests', `Requests ${scan.result.requests ?? ''}`.trim()]] : []),
            ].map(([id, label]) => (
              <button
                key={id}
                type="button"
                role="tab"
                aria-selected={view === id}
                onClick={() => setView(id)}
                className={`-mb-px border-b-2 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${view === id ? 'border-accent text-fg' : 'border-transparent text-fg-muted hover:text-fg'}`}
              >
                {label}
              </button>
            ))}
            {scan.captureId && (
              <button
                type="button"
                onClick={() => openArtifact(`pcap-${scan.captureId}`)}
                className="ml-auto flex items-center gap-1.5 py-2 text-sm text-fg-muted hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <Network className="h-3.5 w-3.5" aria-hidden="true" />
                Open the capture
                <ExternalLink className="h-3 w-3" aria-hidden="true" />
              </button>
            )}
          </div>
          {view === 'overview' && <Overview scan={scan} incident={incident} />}
          {view === 'requests' && scan.captureId && <Requests captureId={scan.captureId} />}
        </div>
      ) : (
        <MicroSkull className="text-lg text-fg-muted" />
      )}
    </Card>
  )
}

export default function UrlAnalysisTab({ incident }) {
  const { retryActiveIncident } = useIncidents()
  const { unlink, refresh: refreshArtifacts, openArtifact } = useArtifacts()
  const menu = useItemMenu(incident)
  const { showToast } = useToast()
  // An address opened on its own (ArtifactPage): no list, no form, no Remove.
  const standalone = Boolean(incident.standalone)
  const scans = incident.data.urls?.scans ?? NO_SCANS

  const [selected, setSelected] = useState(scans[0]?.id ?? null)
  const [details, setDetails] = useState({})
  const [errors, setErrors] = useState({})
  const [address, setAddress] = useState('')
  const [formError, setFormError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [browsing, setBrowsing] = useState(null)
  const [listOpen, setListOpen] = useStoredBoolean('nik.list.urls', true)

  useEffect(() => {
    if (!scans.some((s) => s.id === selected)) setSelected(scans[0]?.id ?? null)
  }, [scans, selected])

  const fetchDetail = useCallback(
    (id) =>
      api
        .get(`/urls/${id}`)
        .then((doc) => setDetails((prev) => ({ ...prev, [id]: doc })))
        .catch((err) => setErrors((prev) => ({ ...prev, [id]: err.message }))),
    [],
  )

  // Fetch the selected scan, and poll it while the browser is visiting.
  const current = scans.find((s) => s.id === selected) ?? null
  const detail = current ? (details[current.id] ?? null) : null
  const scanning = isScanning(detail ?? current)
  useEffect(() => {
    if (!current) return undefined
    if (!details[current.id]) fetchDetail(current.id)
    if (!scanning) return undefined
    const timer = setInterval(() => fetchDetail(current.id), POLL_MS)
    return () => clearInterval(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [current?.id, scanning, fetchDetail])

  // A scan that just finished changed the incident's reference and the artifact list.
  const status = detail?.status
  useEffect(() => {
    if (status !== 'done' && status !== 'error') return
    refreshArtifacts()
    if (!standalone && current && current.status !== status) retryActiveIncident()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status])

  const handleSubmit = async (event) => {
    event.preventDefault()
    const url = urlFromText(address)
    if (!url) {
      setFormError('Type an http or https address.')
      return
    }
    setBusy(true)
    setFormError(null)
    try {
      const scan = await api.post('/artifacts/urls', { url, incident: incident.id })
      setDetails((prev) => ({ ...prev, [scan.id]: scan }))
      setSelected(scan.id)
      setAddress('')
      refreshArtifacts()
      retryActiveIncident()
    } catch (err) {
      setFormError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const handleRescan = async (scan) => {
    setBusy(true)
    try {
      const doc = await api.post(`/urls/${scan.id}/rescan`)
      setDetails((prev) => ({ ...prev, [scan.id]: doc }))
    } catch (err) {
      showToast({ message: `${displayUrl(scan.url)}: ${err.message}` })
    } finally {
      setBusy(false)
    }
  }

  const handleRemove = async (scan) => {
    setBusy(true)
    try {
      await unlink(`url-${scan.id}`, incident.id)
      retryActiveIncident()
    } catch (err) {
      showToast({ message: `${displayUrl(scan.url)}: ${err.message}` })
    } finally {
      setBusy(false)
    }
  }

  const form = (
    <form onSubmit={handleSubmit} className="space-y-2">
      <div className="flex gap-2">
        <input
          aria-label="Address to scan"
          placeholder="https://… (defanged text works too)"
          value={address}
          onChange={(event) => setAddress(event.target.value)}
          className={INPUT}
        />
        <Button type="submit" icon={Search} disabled={busy || !address.trim()}>
          Scan
        </Button>
      </div>
      {formError && (
        <p role="alert" className="font-mono text-xs text-high">
          {formError}
        </p>
      )}
    </form>
  )

  if (scans.length === 0) {
    return (
      <EmptyState
        illustration={<AsciiSkull preset="medium" eyes="closed" tone="muted" />}
        title="No addresses yet"
        message="Give Nik a link from an e-mail or a chat: the isolated browser visits it for you and brings back a screenshot, the redirects, the page's forms and a verdict. Nothing is typed or submitted."
        action={<div className="w-full max-w-xl">{form}</div>}
      />
    )
  }

  const shown = current ? { ...current, ...(detail ?? {}) } : null
  return (
    <div
      className={
        standalone
          ? 'grid gap-4'
          : `grid gap-4 ${listOpen ? 'lg:grid-cols-[280px_minmax(0,1fr)]' : 'lg:grid-cols-[auto_minmax(0,1fr)]'}`
      }
    >
      {standalone ? null : listOpen ? (
        <Card
          title={`Addresses · ${scans.length}`}
          icon={Link2}
          actions={
            <Button
              variant="ghost"
              size="xs"
              icon={PanelLeftClose}
              aria-label="Hide the address list"
              onClick={() => setListOpen(false)}
            />
          }
          bodyClassName="p-0"
        >
          <ul aria-label="Addresses">
            {scans.map((scan) => {
              const badge = scanBadge(details[scan.id] ?? scan)
              return (
                <li
                  key={scan.id}
                  className="border-b border-line-soft"
                  onContextMenu={(event) =>
                    menu(event, {
                      title: displayUrl(scan.url),
                      what: 'address',
                      flaggable: scanFlaggable(scan),
                      ioc: { type: 'url', value: scan.url },
                      timeline: true,
                      actions: [
                        {
                          label: 'Open as an artifact',
                          icon: Boxes,
                          onSelect: () => openArtifact(`url-${scan.id}`),
                        },
                        { label: 'Scan again', icon: RefreshCw, onSelect: () => handleRescan(scan) },
                      ],
                      danger: [{ label: 'Remove from the incident', icon: Trash2, onSelect: () => handleRemove(scan) }],
                    })
                  }
                >
                  <button
                    type="button"
                    onClick={() => setSelected(scan.id)}
                    aria-current={scan.id === selected ? 'true' : undefined}
                    className={`w-full px-3 py-2 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent ${scan.id === selected ? 'bg-panel shadow-[inset_2px_0_0_var(--color-accent)]' : 'hover:bg-panel/60'}`}
                  >
                    <span className="flex items-center gap-1.5 font-mono text-[13px] font-semibold text-fg">
                      {incident.flags?.[`url:${scan.id}`] && (
                        <Flag className="h-3 w-3 shrink-0 text-accent" fill="currentColor" aria-label="Flagged" />
                      )}
                      <span className="truncate">{displayUrl(scan.url)}</span>
                    </span>
                    <span className="mt-1 block">
                      <Badge color={badge.color}>{badge.label}</Badge>
                    </span>
                  </button>
                </li>
              )
            })}
          </ul>
          <div className="border-t border-line p-3">{form}</div>
        </Card>
      ) : (
        <div>
          <Button
            variant="ghost"
            size="xs"
            icon={PanelLeftOpen}
            aria-label="Show the address list"
            onClick={() => setListOpen(true)}
          />
        </div>
      )}

      {shown && (
        <UrlDetail
          key={shown.id}
          scan={shown}
          incident={incident}
          error={errors[shown.id] ?? null}
          busy={busy}
          onRescan={() => handleRescan(shown)}
          onRemove={standalone ? undefined : () => handleRemove(shown)}
          onBrowse={() =>
            setBrowsing({
              url: shown.result?.finalUrl ?? shown.url,
              network: true,
              ...(incident.id ? { incident: incident.id } : {}),
            })
          }
        />
      )}
      <RemoteBrowser request={browsing} onClose={() => setBrowsing(null)} />
    </div>
  )
}
