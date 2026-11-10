import { useCallback, useEffect, useState } from 'react'
import { Bug, Download, FileDown, KeyRound, RefreshCw, Trash2 } from 'lucide-react'
import { AsciiSkull, Badge, Button, Card, StatCard } from '../../ui/index.js'
import PacketView from './PacketView.jsx'
import RequestLog from './RequestLog.jsx'
import { IocValue } from '../../../context/IocLookupContext.jsx'
import { api, apiUrl } from '../../../services/api.js'
import { formatBytes } from '../../../utils/events.js'
import { formatDateTime } from '../../../utils/time.js'

/*
 * One capture: its state, the figures of the analysis, and the views
 * Packets (Wireshark) · Requests (isolated browser sessions: DevTools) ·
 * Objects (Export Objects) · Summary (hosts, DNS, HTTP, TLS server names,
 * submissions, beacons, Expert Info).
 */

const STATUS = {
  live: { label: 'session open', color: 'cyan' },
  indexing: { label: 'analysing…', color: 'amber' },
  ready: { label: 'ready', color: 'emerald' },
  error: { label: 'error', color: 'red' },
  stored: { label: 'stored, not analysed', color: 'slate' },
}

function List({ title, items, render, empty = '—' }) {
  return (
    <section className="space-y-1">
      <h3 className="font-mono text-xs uppercase tracking-wider text-fg-muted">
        {title} · {items.length}
      </h3>
      {items.length ? (
        <ul className="max-h-64 space-y-0.5 overflow-auto font-mono text-xs">{items.map(render)}</ul>
      ) : (
        <p className="font-mono text-xs text-fg-subtle">{empty}</p>
      )}
    </section>
  )
}

function Summary({ capture }) {
  const s = capture.summary ?? {}
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <List
        title="Submissions (POST, PUT, PATCH)"
        items={[...(capture.meta?.held ?? []).map((h) => ({ ...h, held: true })), ...(s.posts ?? [])]}
        render={(p, i) => (
          <li key={i} className="break-all">
            {p.held && <Badge color="red">held</Badge>} <span className="text-fg-muted">{p.method}</span>{' '}
            <IocValue type="url" value={p.url} />
          </li>
        )}
      />
      <List
        title="Periodic connections (beacons)"
        items={s.beacons ?? []}
        empty="No regular connection pattern."
        render={(b, i) => (
          <li key={i}>
            <IocValue type="ip" value={b.destination} />:{b.port} ·{' '}
            <span className="text-high">
              {b.count} connections every {b.interval} s
            </span>{' '}
            <span className="text-fg-muted">(jitter {Math.round(b.jitter * 100)} %)</span>
          </li>
        )}
      />
      <List
        title="DNS"
        items={s.dns ?? []}
        render={(d) => (
          <li key={d.name} className="break-all">
            <IocValue type="domain" value={d.name} />
            {d.answers.length > 0 && <span className="text-fg-muted"> → {d.answers.join(', ')}</span>}
          </li>
        )}
      />
      <List
        title="TLS server names (SNI)"
        items={s.tlsServerNames ?? []}
        render={(t) => (
          <li key={t.name}>
            <IocValue type="domain" value={t.name} /> <span className="text-fg-muted">× {t.count}</span>
          </li>
        )}
      />
      <List
        title="HTTP requests"
        items={s.http ?? []}
        render={(h) => (
          <li key={h.url} className="break-all">
            <span className="text-fg-muted">{h.method}</span> <IocValue type="url" value={h.url} />
            <span className="text-fg-muted"> × {h.count}</span>
          </li>
        )}
      />
      <List
        title="Hosts by bytes"
        items={s.hosts ?? []}
        render={(h) => (
          <li key={h.address}>
            {h.public ? <IocValue type="ip" value={h.address} /> : <span className="text-fg-muted">{h.address}</span>}{' '}
            <span className="text-fg-muted">
              {h.packets} packets · {formatBytes(h.bytes)}
            </span>
          </li>
        )}
      />
      <List
        title="Protocols"
        items={s.protocols ?? []}
        render={(p) => (
          <li key={p.name}>
            {p.name} <span className="text-fg-muted">× {p.packets}</span>
          </li>
        )}
      />
      <List
        title="Expert Info"
        items={Object.entries(s.expert ?? {})}
        render={([severity, count]) => (
          <li key={severity}>
            <span className={severity === 'Error' ? 'text-high' : severity === 'Warning' ? 'text-med' : ''}>
              {severity}
            </span>{' '}
            <span className="text-fg-muted">× {count}</span>
          </li>
        )}
      />
    </div>
  )
}

function Objects({ capture, onDownload, onSend, sending }) {
  const objects = capture.summary?.objects ?? []
  if (!objects.length)
    return <p className="font-mono text-xs text-fg-muted">No object to export (HTTP, SMB, FTP, TFTP, IMF, DICOM).</p>
  return (
    <table className="w-full table-fixed border-collapse font-mono text-xs">
      <thead>
        <tr className="border-b border-line text-left text-fg-muted">
          <th className="w-14 py-1 font-normal">Packet</th>
          <th className="w-20 py-1 font-normal">Protocol</th>
          <th className="py-1 font-normal">File / host</th>
          <th className="w-24 py-1 text-right font-normal">Size</th>
          <th className="w-72 py-1 font-normal" />
        </tr>
      </thead>
      <tbody>
        {objects.map((o) => (
          <tr key={o.token} className="border-b border-line-soft align-top">
            <td className="py-1.5">{o.frame}</td>
            <td className="py-1.5 uppercase text-fg-muted">{o.tap.replace('eo:', '')}</td>
            <td className="break-all py-1.5">
              {o.name || '(no name)'}{' '}
              <span className="text-fg-muted">
                · {o.host} · {o.type}
              </span>
              {o.sha256 && (
                <span className="mt-0.5 block text-[11px] text-fg-muted">
                  sha256 <IocValue type="sha256" value={o.sha256} />
                </span>
              )}
            </td>
            <td className="py-1.5 text-right text-fg-muted">{formatBytes(o.size)}</td>
            <td className="py-1.5 text-right">
              <span className="flex justify-end gap-1">
                <Button size="xs" variant="ghost" icon={Download} onClick={() => onDownload(o)}>
                  Zip
                </Button>
                <Button
                  size="xs"
                  variant="secondary"
                  icon={Bug}
                  onClick={() => onSend(o)}
                  disabled={sending === o.token}
                >
                  {sending === o.token ? 'Sending…' : 'Send to Malware Analysis'}
                </Button>
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/**
 * @param {{ incident: object, capture: object (reference), detail: object | null, error: string | null,
 *   onRemove, removing, onReanalyse, onKeylog, onRemoveKeylog, onDownloadObject, onSendObject, sending,
 *   onFlag }} props
 */
export default function CaptureDetail({
  incident,
  capture,
  detail,
  error,
  onRemove,
  removing,
  onReanalyse,
  onKeylog,
  onRemoveKeylog,
  onDownloadObject,
  onSendObject,
  sending,
  onFlag,
}) {
  const browser = capture.kind === 'browser'
  const ready = capture.status === 'ready'
  const views = [
    ...(ready ? [{ id: 'packets', label: 'Packets' }] : []),
    ...(browser ? [{ id: 'requests', label: 'Requests' }] : []),
    ...(ready
      ? [
          { id: 'objects', label: 'Objects' },
          { id: 'summary', label: 'Summary' },
        ]
      : []),
  ]
  const [view, setView] = useState(null)
  const current = views.some((v) => v.id === view) ? view : views[0]?.id
  const [requests, setRequests] = useState([])

  const loadRequests = useCallback(() => {
    if (!browser) return
    api
      .get(`/captures/${capture.id}/requests`)
      .then((res) => setRequests(res.entries))
      .catch(() => {})
  }, [browser, capture.id])
  useEffect(() => loadRequests(), [loadRequests, capture.status])
  const loadEntry = useCallback((id) => api.get(`/captures/${capture.id}/requests/${id}`), [capture.id])

  const status = STATUS[capture.status] ?? STATUS.stored
  const s = detail?.summary ?? {}
  const duration = capture.first && capture.last ? (capture.last - capture.first) / 1000 : null

  return (
    <Card
      title={
        <span className="flex min-w-0 flex-wrap items-center gap-2">
          <span className="truncate">{capture.fileName}</span>
          <Badge color={status.color}>{status.label}</Badge>
          {browser && <Badge color="cyan">isolated browser · reconstructed</Badge>}
          {capture.keylog && <Badge color="emerald">TLS keys</Badge>}
        </span>
      }
      actions={
        <>
          {!browser && (
            <Button
              variant="ghost"
              size="xs"
              icon={KeyRound}
              onClick={onKeylog}
              disabled={capture.status === 'indexing'}
            >
              {capture.keylog ? 'Replace TLS keys' : 'Add TLS keys'}
            </Button>
          )}
          {capture.keylog && (
            <Button variant="ghost" size="xs" onClick={onRemoveKeylog}>
              Remove keys
            </Button>
          )}
          {browser && capture.status !== 'live' && (
            <a
              href={apiUrl(`/captures/${capture.id}/har`)}
              className="inline-flex items-center gap-1 px-2 py-1 font-mono text-xs text-link hover:underline"
            >
              <FileDown className="h-3.5 w-3.5" aria-hidden="true" /> HAR
            </a>
          )}
          {capture.status !== 'live' && (
            <a
              href={apiUrl(`/captures/${capture.id}/file`)}
              className="inline-flex items-center gap-1 px-2 py-1 font-mono text-xs text-link hover:underline"
            >
              <Download className="h-3.5 w-3.5" aria-hidden="true" /> {browser ? 'pcapng' : 'Capture'}
            </a>
          )}
          <Button
            variant="ghost"
            size="xs"
            icon={RefreshCw}
            onClick={onReanalyse}
            disabled={['live', 'indexing'].includes(capture.status)}
          >
            Re-analyse
          </Button>
          <Button variant="ghost" size="xs" icon={Trash2} onClick={onRemove} disabled={removing}>
            Remove
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {error && (
          <p role="alert" className="font-mono text-xs text-high">
            {error}
          </p>
        )}
        {capture.status === 'error' && (
          <p role="alert" className="font-mono text-xs text-high">
            {capture.error}
          </p>
        )}
        {capture.status === 'indexing' && (
          <div aria-busy="true" className="flex flex-col items-center gap-3 py-6 text-center font-mono">
            <AsciiSkull preset="medium" />
            <p role="status" className="text-sm text-fg-muted">
              Wireshark is reading the capture…
            </p>
          </div>
        )}
        {capture.status === 'stored' && <p className="font-mono text-xs text-fg-muted">{capture.error}</p>}
        {(ready || browser) && (
          <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
            <StatCard
              label="Packets"
              value={(capture.packets ?? 0).toLocaleString('en-US')}
              hint={
                duration !== null
                  ? `${duration.toFixed(1)} s · ${formatBytes(capture.size)}`
                  : formatBytes(capture.size)
              }
            />
            <StatCard
              label={browser ? 'Requests' : 'Submissions'}
              value={browser ? requests.length : capture.posts}
              tone={capture.held?.length ? 'danger' : 'default'}
              hint={browser ? `${capture.held?.length ?? 0} held` : 'POST, PUT, PATCH'}
            />
            <StatCard
              label="Beacons"
              value={capture.beacons?.length ?? 0}
              tone={capture.beacons?.length ? 'danger' : 'default'}
              hint="regular connections"
            />
            <StatCard
              label="Objects"
              value={capture.objects ?? 0}
              hint={s.expert ? `${s.expert.Warning ?? 0} warnings · ${s.expert.Error ?? 0} errors` : 'exportable'}
            />
          </div>
        )}
        <p className="font-mono text-[11px] text-fg-muted">
          {capture.sha256 && `sha256 ${capture.sha256} · `}
          {capture.label && `${capture.label} · `}
          added {formatDateTime(Date.parse(capture.createdAt))} by {capture.createdBy}
        </p>
        {views.length > 0 && (
          <div role="tablist" aria-label="Capture views" className="flex flex-wrap gap-1 border-b border-line">
            {views.map((item) => (
              <button
                key={item.id}
                type="button"
                role="tab"
                aria-selected={current === item.id}
                onClick={() => setView(item.id)}
                className={[
                  '-mb-px whitespace-nowrap border-b-2 px-3 py-2 text-sm font-medium transition-colors',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                  current === item.id
                    ? 'border-accent-strong text-accent'
                    : 'border-transparent text-fg-muted hover:text-fg',
                ].join(' ')}
              >
                {item.label}
              </button>
            ))}
          </div>
        )}
        {current === 'packets' && <PacketView capture={capture} flags={incident.flags ?? {}} onFlag={onFlag} />}
        {current === 'requests' && (
          <RequestLog entries={requests} loadEntry={loadEntry} live={capture.status === 'live'} />
        )}
        {current === 'objects' && detail && (
          <Objects capture={detail} onDownload={onDownloadObject} onSend={onSendObject} sending={sending} />
        )}
        {current === 'summary' && detail && <Summary capture={detail} />}
      </div>
    </Card>
  )
}
