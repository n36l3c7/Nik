import { useEffect, useMemo, useState } from 'react'
import { Search, X } from 'lucide-react'
import { useIocLookup } from '../../../context/IocLookupContext.jsx'
import { Badge } from '../../ui/index.js'
import { hexRows, formatOffset } from '../../../domain/mail.js'
import {
  REQUEST_TYPES,
  base64Text,
  filterRequests,
  formatBytesShort,
  formatMs,
  fromBase64,
  header,
  isText,
  payloadFields,
  requestName,
  requestStatus,
  timeSpan,
  waterfall,
} from '../../../domain/network.js'
import { formatDateTime } from '../../../lib/time.js'

/*
 * The isolated browser's requests as DevTools' Network panel shows them: a
 * filterable list with a waterfall, and the selected request's Headers,
 * Payload, Preview, Response, Timing and (WebSocket) Messages. Refused and
 * held requests stay in the list, in red, with the reason. HTML previews are
 * drawn in a frame that runs nothing and loads nothing.
 *
 * @param {{ entries: object[], loadEntry: (id: number) => Promise<object>, live?: boolean }} props
 */

const TONES = { high: 'text-high', med: 'text-med', ok: 'text-fg', muted: 'text-fg-muted' }
const PREVIEW_CSP = "default-src 'none'; img-src data:; style-src 'unsafe-inline'"
// Control characters below TAB in the first bytes: shown as hex, not text.
const looksBinary = (text) => [...text.slice(0, 200)].some((c) => c.charCodeAt(0) < 9)

function FilterBar({ filter, setFilter, count, total }) {
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-line px-2 py-1.5 font-mono text-[11px]">
      <label className="flex min-w-[12rem] flex-1 items-center gap-1 border border-line bg-canvas px-2 py-1">
        <Search className="h-3 w-3 text-fg-muted" aria-hidden="true" />
        <input
          value={filter.text}
          onChange={(e) => setFilter({ ...filter, text: e.target.value })}
          placeholder="Filter URLs"
          aria-label="Filter requests"
          className="min-w-0 flex-1 bg-transparent text-fg outline-none"
        />
      </label>
      <span className="flex flex-wrap gap-0.5" role="tablist" aria-label="Request types">
        {REQUEST_TYPES.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={filter.type === t.id}
            onClick={() => setFilter({ ...filter, type: t.id })}
            className={[
              'px-1.5 py-0.5',
              filter.type === t.id ? 'bg-accent-soft text-accent-fg' : 'text-fg-muted hover:text-fg',
            ].join(' ')}
          >
            {t.label}
          </button>
        ))}
      </span>
      <label className="flex items-center gap-1 text-fg-muted">
        <input
          type="checkbox"
          checked={filter.refused}
          onChange={(e) => setFilter({ ...filter, refused: e.target.checked })}
          className="accent-accent"
        />
        Blocked / held
      </label>
      <label className="flex items-center gap-1 text-fg-muted">
        <input
          type="checkbox"
          checked={filter.posts}
          onChange={(e) => setFilter({ ...filter, posts: e.target.checked })}
          className="accent-accent"
        />
        Submissions only
      </label>
      <span className="text-fg-subtle">
        {count} / {total}
      </span>
    </div>
  )
}

function Pairs({ pairs }) {
  if (!pairs?.length) return <p className="text-fg-subtle">—</p>
  return (
    <dl className="grid grid-cols-[minmax(8rem,14rem)_minmax(0,1fr)] gap-x-3">
      {pairs.map(([name, value], i) => (
        <div key={i} className="contents">
          <dt className="py-0.5 text-fg-muted">{name}</dt>
          <dd className="break-all py-0.5 text-fg">{value}</dd>
        </div>
      ))}
    </dl>
  )
}

function Section({ title, children }) {
  return (
    <section className="space-y-1">
      <h4 className="text-[11px] font-semibold uppercase tracking-wider text-fg-muted">{title}</h4>
      {children}
    </section>
  )
}

function Hex({ base64 }) {
  const rows = hexRows(fromBase64(base64).slice(0, 64 * 1024))
  return (
    <pre className="max-h-80 overflow-auto bg-canvas p-2 text-[11px] leading-4">
      {rows.map((row) => (
        <div key={row.offset} className="whitespace-pre">
          <span className="text-fg-subtle">{formatOffset(row.offset)}</span> {row.hex.join(' ').padEnd(47, ' ')}{' '}
          <span className="text-accent-fg">{row.ascii}</span>
        </div>
      ))}
    </pre>
  )
}

function Body({ part, preview }) {
  if (!part?.body) {
    return (
      <p className="text-fg-subtle">
        {part?.bodyTruncated
          ? `Not kept: ${formatBytesShort(part.bodySize)} over the size limit (SHA-256 ${part.bodySha256}).`
          : 'No body.'}
      </p>
    )
  }
  const mime = part.mimeType || header(part.headers, 'content-type')
  if (preview && /html/i.test(mime)) {
    return (
      <iframe
        title="Response preview (sandboxed)"
        sandbox=""
        srcDoc={`<meta http-equiv="Content-Security-Policy" content="${PREVIEW_CSP}">${base64Text(part.body)}`}
        className="h-80 w-full border border-line bg-white"
      />
    )
  }
  if (preview && /^image\/(png|jpeg|gif|webp|bmp)/i.test(mime)) {
    return <img src={`data:${mime};base64,${part.body}`} alt="Response preview" className="max-h-80 max-w-full" />
  }
  if (isText(mime) || (!mime && !looksBinary(base64Text(part.body)))) {
    let text = base64Text(part.body)
    if (preview && /json/i.test(mime)) {
      try {
        text = JSON.stringify(JSON.parse(text), null, 2)
      } catch {
        // Not valid JSON: shown as it is.
      }
    }
    return <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all bg-canvas p-2 text-fg">{text}</pre>
  }
  return <Hex base64={part.body} />
}

function Timing({ entry }) {
  const t = entry.timing
  if (!t)
    return (
      <p className="text-fg-subtle">
        No timing: the request {entry.state === 'done' ? 'was served from cache' : 'never left'}.
      </p>
    )
  const phases = [
    ['DNS lookup', t.dns],
    ['Initial connection', t.connect],
    ['SSL', t.ssl],
    ['Waiting for server', t.wait],
    ['Content download', t.receive],
  ]
  const total = t.total > 0 ? t.total : 1
  return (
    <dl className="grid grid-cols-[10rem_minmax(0,1fr)_5rem] items-center gap-x-3 gap-y-1">
      {phases.map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="text-fg-muted">{label}</dt>
          <dd className="h-2 bg-canvas">
            {value > 0 && <div className="h-2 bg-info" style={{ width: `${Math.min(100, (value / total) * 100)}%` }} />}
          </dd>
          <dd className="text-right text-fg">{formatMs(value)}</dd>
        </div>
      ))}
      <dt className="font-semibold text-fg">Total</dt>
      <dd />
      <dd className="text-right font-semibold text-fg">{formatMs(t.total)}</dd>
    </dl>
  )
}

const DETAIL_TABS = ['Headers', 'Payload', 'Preview', 'Response', 'Timing', 'Messages']

function Detail({ entry, onClose }) {
  const tabs = DETAIL_TABS.filter(
    (t) =>
      (t !== 'Payload' || entry.request?.body || entry.request?.bodyTruncated) &&
      (t !== 'Messages' || entry.frames) &&
      (!['Preview', 'Response'].includes(t) || entry.response?.status),
  )
  const [tab, setTab] = useState('Headers')
  const current = tabs.includes(tab) ? tab : 'Headers'
  const response = entry.response ?? {}
  const fields = payloadFields(entry.request?.body, header(entry.request?.headers, 'content-type'))
  return (
    <div className="flex min-h-0 flex-col border-l border-line">
      <div className="flex items-center gap-1 border-b border-line px-1">
        <button
          type="button"
          onClick={onClose}
          aria-label="Close the request details"
          className="p-1 text-fg-muted hover:text-fg"
        >
          <X className="h-3.5 w-3.5" />
        </button>
        <div role="tablist" aria-label="Request details" className="flex flex-wrap">
          {tabs.map((t) => (
            <button
              key={t}
              type="button"
              role="tab"
              aria-selected={current === t}
              onClick={() => setTab(t)}
              className={[
                '-mb-px border-b-2 px-2 py-1.5 text-[11px]',
                current === t ? 'border-accent-strong text-accent' : 'border-transparent text-fg-muted hover:text-fg',
              ].join(' ')}
            >
              {t}
            </button>
          ))}
        </div>
      </div>
      <div className="min-h-0 flex-1 space-y-3 overflow-auto p-3 text-[11px]">
        {current === 'Headers' && (
          <>
            <Section title="General">
              <Pairs
                pairs={[
                  ['Request URL', entry.url],
                  ['Request Method', entry.method],
                  ['Status', response.status ? `${response.status} ${response.statusText ?? ''}` : entry.state],
                  ...(entry.reason || entry.error ? [['Reason', entry.reason || entry.error]] : []),
                  ...(response.serverIp
                    ? [['Remote Address', `${response.serverIp}:${response.serverPort ?? ''}`]]
                    : []),
                  ['Started', formatDateTime(entry.startedAt)],
                  ...(response.tls
                    ? [
                        ['TLS', response.tls.protocol ?? ''],
                        ['Certificate', `${response.tls.subjectName ?? ''} · issued by ${response.tls.issuer ?? ''}`],
                      ]
                    : []),
                ]}
              />
            </Section>
            {response.headers?.length > 0 && (
              <Section title="Response Headers">
                <Pairs pairs={response.headers} />
              </Section>
            )}
            <Section title="Request Headers">
              <Pairs pairs={entry.request?.headers} />
            </Section>
          </>
        )}
        {current === 'Payload' &&
          (fields ? (
            <Section title={entry.state === 'held' ? 'Form data (held, never sent)' : 'Form data'}>
              <Pairs pairs={fields} />
            </Section>
          ) : (
            <Section title="Request body">
              <Body part={{ ...entry.request, mimeType: header(entry.request?.headers, 'content-type') }} />
            </Section>
          ))}
        {current === 'Preview' && <Body part={response} preview />}
        {current === 'Response' && <Body part={response} />}
        {current === 'Timing' && <Timing entry={entry} />}
        {current === 'Messages' && (
          <table className="w-full table-fixed border-collapse">
            <tbody>
              {(entry.frames ?? []).map((f, i) => (
                <tr key={i} className={f.direction === 'sent' ? 'bg-info-soft/30' : ''}>
                  <td className="w-6 align-top">{f.direction === 'sent' ? '↑' : '↓'}</td>
                  <td className="break-all py-0.5 align-top text-fg">
                    {f.binary ? `binary, ${formatBytesShort(f.size)}` : f.text}
                  </td>
                  <td className="w-24 py-0.5 text-right align-top text-fg-muted">
                    {new Date(f.time).toISOString().slice(11, 23)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

export default function RequestLog({ entries, loadEntry, live = false }) {
  // A request is its address: flag it, see where else it was seen, copy it.
  const { iocMenu } = useIocLookup()
  const [filter, setFilter] = useState({ type: 'all', text: '', refused: false, posts: false })
  const [selected, setSelected] = useState(null)
  const [detail, setDetail] = useState(null)
  const [error, setError] = useState(null)
  const shown = useMemo(() => filterRequests(entries, filter), [entries, filter])
  const { start, span } = useMemo(() => timeSpan(entries), [entries])
  const version = entries.find((e) => e.id === selected)?.seq

  useEffect(() => {
    if (selected === null) return undefined
    let cancelled = false
    loadEntry(selected)
      .then((full) => !cancelled && (setDetail(full), setError(null)))
      .catch((err) => !cancelled && setError(err.message))
    return () => {
      cancelled = true
    }
  }, [selected, version, loadEntry])

  return (
    <div className="flex h-[60vh] min-h-0 flex-col border border-line bg-panel font-mono">
      <FilterBar filter={filter} setFilter={setFilter} count={shown.length} total={entries.length} />
      <div className={`grid min-h-0 flex-1 ${selected !== null ? 'grid-cols-[minmax(0,2fr)_minmax(0,3fr)]' : ''}`}>
        <div className="min-h-0 overflow-auto">
          <table className="w-full table-fixed border-collapse text-[11px]">
            <thead className="sticky top-0 bg-panel text-left text-fg-muted">
              <tr className="border-b border-line">
                <th className="px-2 py-1 font-normal">Name</th>
                {selected === null && (
                  <>
                    <th className="w-16 px-2 py-1 font-normal">Method</th>
                    <th className="w-16 px-2 py-1 font-normal">Status</th>
                    <th className="w-20 px-2 py-1 font-normal">Type</th>
                    <th className="w-16 px-2 py-1 text-right font-normal">Size</th>
                    <th className="w-16 px-2 py-1 text-right font-normal">Time</th>
                    <th className="w-[22%] px-2 py-1 font-normal">Waterfall</th>
                  </>
                )}
              </tr>
            </thead>
            <tbody>
              {shown.map((entry) => {
                const status = requestStatus(entry)
                const bar = waterfall(entry, start, span)
                const refused = ['blocked', 'held'].includes(entry.state)
                return (
                  <tr
                    key={entry.id}
                    onClick={() => setSelected(entry.id)}
                    onContextMenu={(event) => iocMenu(event, 'url', entry.url)}
                    aria-selected={entry.id === selected}
                    className={[
                      'cursor-pointer border-b border-line-soft',
                      entry.id === selected ? 'bg-accent-soft' : refused ? 'bg-high-soft/40' : 'hover:bg-raised',
                    ].join(' ')}
                  >
                    <td className={`truncate px-2 py-1 ${refused ? 'text-high' : 'text-fg'}`} title={entry.url}>
                      {entry.state === 'held' && (
                        <Badge color="red" className="mr-1">
                          held
                        </Badge>
                      )}
                      {requestName(entry.url)}
                    </td>
                    {selected === null && (
                      <>
                        <td className="px-2 py-1 text-fg">{entry.method}</td>
                        <td className={`px-2 py-1 ${TONES[status.tone]}`} title={entry.reason || entry.error || ''}>
                          {status.text}
                        </td>
                        <td className="truncate px-2 py-1 text-fg-muted">{entry.resourceType}</td>
                        <td className="px-2 py-1 text-right text-fg-muted">
                          {formatBytesShort(entry.response?.bodySize)}
                        </td>
                        <td className="px-2 py-1 text-right text-fg-muted">{formatMs(entry.timing?.total)}</td>
                        <td className="px-2 py-1">
                          <div className="relative h-2 bg-canvas">
                            <div
                              className={`absolute h-2 ${refused ? 'bg-high' : 'bg-info'}`}
                              style={{ left: `${bar.offset}%`, width: `${bar.width}%` }}
                            />
                          </div>
                        </td>
                      </>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </table>
          {!entries.length && (
            <p className="p-4 text-center text-[11px] text-fg-muted">
              {live ? 'No request yet: interact with the page.' : 'No request was recorded.'}
            </p>
          )}
        </div>
        {selected !== null &&
          (error ? (
            <p role="alert" className="p-3 text-[11px] text-high">
              {error}
            </p>
          ) : detail && detail.id === selected ? (
            <Detail entry={detail} onClose={() => setSelected(null)} />
          ) : (
            <p className="p-3 text-[11px] text-fg-muted">Loading…</p>
          ))}
      </div>
    </div>
  )
}
