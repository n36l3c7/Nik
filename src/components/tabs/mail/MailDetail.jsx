import { useState } from 'react'
import { RefreshCw, Trash2 } from 'lucide-react'
import { AsciiSkull, Badge, Button, Card, StatCard } from '../../ui/index.js'
import MailBody from './MailBody.jsx'
import MailHeaders from './MailHeaders.jsx'
import MailLinks from './MailLinks.jsx'
import MailAttachments from './MailAttachments.jsx'
import { IocValue } from '../../../context/IocLookupContext.jsx'
import { formatDateTime } from '../../../utils/time.js'
import { authResult, resultColor, verdictMeta } from '../../../utils/mail.js'

/*
 * One message, in full: the verdict with the evidence behind it, the sender
 * and its mismatches, then the views Overview · Headers · Body · Links ·
 * Attachments. The analysis is fetched by the parent (GET /api/mails/{sha}).
 */

const VIEWS = [
  { id: 'overview', label: 'Overview' },
  { id: 'headers', label: 'Headers' },
  { id: 'body', label: 'Body' },
  { id: 'links', label: 'Links' },
  { id: 'attachments', label: 'Attachments' },
]
const SEVERITY_COLOR = { high: 'red', medium: 'amber', low: 'slate' }

function Address({ label, value, warn = false }) {
  if (!value) return null
  return (
    <>
      <dt className="text-fg-muted">{label}</dt>
      <dd className={`min-w-0 break-all ${warn ? 'text-high' : 'text-fg'}`}>{value}</dd>
    </>
  )
}

function Overview({ analysis }) {
  const who = analysis.sender
  const fromDomain = who.from.domain
  const replyOther = who.replyTo.some((r) => !r.address.toLowerCase().endsWith(`@${fromDomain}`))
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <section className="space-y-2">
        <h3 className="font-mono text-xs uppercase tracking-wider text-fg-muted">Why this verdict</h3>
        {analysis.findings.length ? (
          <ul className="space-y-1 font-mono text-xs">
            {analysis.findings.map((f) => (
              <li key={f.id} className="grid grid-cols-[2.5rem_3.75rem_minmax(0,1fr)] items-start gap-2">
                <span className="text-right tabular-nums text-fg-muted">{f.points ? `+${f.points}` : '·'}</span>
                <Badge color={SEVERITY_COLOR[f.severity]} className="justify-center">
                  {f.severity}
                </Badge>
                <span className="break-words text-fg">{f.label}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="font-mono text-xs text-fg-muted">
            Nothing stood out. This is not proof the message is safe: read the body and check the links.
          </p>
        )}
      </section>
      <section className="space-y-2">
        <h3 className="font-mono text-xs uppercase tracking-wider text-fg-muted">Sender</h3>
        <dl className="grid grid-cols-[7rem_minmax(0,1fr)] gap-x-3 gap-y-1 font-mono text-xs">
          <dt className="text-fg-muted">From</dt>
          <dd className="min-w-0 break-all text-fg">
            {who.from.name && <span className="text-fg-muted">“{who.from.name}” </span>}
            {who.from.address ? <IocValue type="email" value={who.from.address} /> : '—'}
          </dd>
          <Address label="Reply-To" value={who.replyTo.map((r) => r.address).join(', ')} warn={replyOther} />
          <Address
            label="Return-Path"
            value={who.returnPath}
            warn={Boolean(who.returnPathDomain && fromDomain && !who.returnPathDomain.endsWith(fromDomain))}
          />
          <Address label="Sender" value={who.sender} />
          <Address label="To" value={who.to.map((r) => r.address).join(', ')} />
          <Address label="Cc" value={who.cc.map((r) => r.address).join(', ')} />
          <Address label="Date" value={who.date ? formatDateTime(who.date) : ''} />
          <Address label="Message-ID" value={who.messageId} />
          <Address label="Client" value={who.client} />
          {analysis.originIp && (
            <>
              <dt className="text-fg-muted">Sending IP</dt>
              <dd>
                <IocValue type="ip" value={analysis.originIp} />
              </dd>
            </>
          )}
          {who.originatingIp && (
            <>
              <dt className="text-fg-muted">Client IP</dt>
              <dd>
                <IocValue type="ip" value={who.originatingIp} />
              </dd>
            </>
          )}
        </dl>
        {analysis.body.pressure.length > 0 && (
          <div className="space-y-1 pt-2">
            <h3 className="font-mono text-xs uppercase tracking-wider text-fg-muted">Pressure in the text</h3>
            <ul className="space-y-0.5 font-mono text-xs">
              {analysis.body.pressure.map((p) => (
                <li key={p.kind}>
                  <span className="text-fg-muted">{p.kind}:</span>{' '}
                  <span className="text-med">{p.phrases.map((x) => `“${x}”`).join(', ')}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>
    </div>
  )
}

/**
 * @param {{
 *   incident: object, message: object, detail: object | null, error: string | null,
 *   onRemove: () => void, removing: boolean, onReanalyse: () => void, reanalysing: boolean,
 *   onDownload: (item: object) => void, onSend: (item: object) => void, sending: string | null,
 *   onOpen: (item: object, kind: 'document'|'html') => void, onOpenUrl: (url: string) => void,
 *   previews: { documents: boolean, browser: boolean } | null,
 * }} props
 */
export default function MailDetail({
  incident,
  message,
  detail,
  error,
  onRemove,
  removing,
  onReanalyse,
  reanalysing,
  onDownload,
  onSend,
  sending,
  onOpen,
  onOpenUrl,
  previews,
}) {
  const [view, setView] = useState('overview')
  const analysis = detail?.analysis ?? null
  const verdict = verdictMeta(analysis?.verdict ?? message.verdict)

  const header = (
    <span className="flex min-w-0 flex-wrap items-center gap-2">
      <span className="truncate">{message.subject || message.fileName}</span>
      <Badge color={verdict.color}>
        {verdict.label} · {analysis?.score ?? message.score}
      </Badge>
      <Badge color="cyan">.{message.format}</Badge>
    </span>
  )

  const serious = (findings) => findings.some((f) => f.severity !== 'low')
  const flaggedLinks = analysis ? analysis.links.filter((l) => serious(l.findings)).length : 0
  const flaggedAttachments = analysis ? analysis.attachments.filter((a) => serious(a.findings)).length : 0
  const counts = analysis
    ? { links: analysis.links.length, attachments: analysis.attachments.length, headers: analysis.headers.length }
    : {}

  return (
    <Card
      title={header}
      actions={
        <>
          <Button
            variant="ghost"
            size="xs"
            icon={RefreshCw}
            onClick={onReanalyse}
            disabled={reanalysing || !analysis}
            title="Analyse the stored message again (repeats the DNS checks; applies Settings → Mail)"
          >
            {reanalysing ? 'Re-analysing…' : 'Re-analyse'}
          </Button>
          <Button
            variant="ghost"
            size="xs"
            icon={Trash2}
            onClick={onRemove}
            disabled={removing}
            title="Remove the message from this incident"
          >
            Remove
          </Button>
        </>
      }
    >
      {error ? (
        <div className="flex flex-col items-center gap-3 py-8 text-center font-mono">
          <AsciiSkull preset="medium" eyes="x" tone="muted" />
          <p role="alert" className="text-sm text-high">
            {error}
          </p>
        </div>
      ) : !analysis ? (
        <div aria-busy="true" className="flex flex-col items-center gap-3 py-8 text-center font-mono">
          <AsciiSkull preset="medium" />
          <p role="status" className="text-sm text-fg-muted">
            Loading the analysis…
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {detail.stale && (
            <p className="flex flex-wrap items-center justify-between gap-2 border-l-2 border-med-line bg-med-soft px-3 py-2 font-mono text-xs text-med-fg">
              <span>This message was analysed by an older engine.</span>
              <Button variant="secondary" size="xs" icon={RefreshCw} onClick={onReanalyse} disabled={reanalysing}>
                Re-analyse now
              </Button>
            </p>
          )}
          <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
            <StatCard label="Verdict" value={analysis.score} tone={verdict.tone} hint={`${verdict.label} · of 100`} />
            <div className="flex flex-col justify-center gap-1.5 border border-line bg-panel px-4 py-3">
              <span className="text-xs text-fg-muted">Authentication</span>
              <span className="flex flex-wrap gap-1">
                {['spf', 'dkim', 'dmarc'].map((method) => {
                  const r = authResult(analysis.auth, method)
                  return (
                    <Badge
                      key={method}
                      color={resultColor(r.result)}
                      title={`${r.source === 'nik' ? 'Checked by Nik' : r.source === 'server' ? 'Your mail server' : r.source === 'header' ? 'Unverified header' : 'No result'}${r.detail ? `: ${r.detail}` : ''}`}
                    >
                      {method.toUpperCase()} {r.result}
                    </Badge>
                  )
                })}
              </span>
            </div>
            <StatCard
              label="Links"
              value={analysis.links.length}
              tone={flaggedLinks ? 'danger' : 'default'}
              hint={`${flaggedLinks} suspicious`}
            />
            <StatCard
              label="Attachments"
              value={analysis.attachments.length}
              tone={flaggedAttachments ? 'danger' : 'default'}
              hint={`${flaggedAttachments} suspicious`}
            />
          </div>

          <div role="tablist" aria-label="Message views" className="flex flex-wrap gap-1 border-b border-line">
            {VIEWS.map((item) => {
              const active = view === item.id
              const count = counts[item.id] ?? null
              return (
                <button
                  key={item.id}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  onClick={() => setView(item.id)}
                  className={[
                    '-mb-px flex items-center gap-2 whitespace-nowrap border-b-2 px-3 py-2 text-sm font-medium transition-colors',
                    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                    active ? 'border-accent-strong text-accent' : 'border-transparent text-fg-muted hover:text-fg',
                  ].join(' ')}
                >
                  {item.label}
                  {count !== null && (
                    <span className="rounded-full bg-canvas px-1.5 text-xs tabular-nums text-fg-muted">{count}</span>
                  )}
                </button>
              )
            })}
          </div>

          {view === 'overview' && <Overview analysis={analysis} />}
          {view === 'headers' && <MailHeaders analysis={analysis} />}
          {view === 'body' && <MailBody message={message} analysis={analysis} />}
          {view === 'links' && <MailLinks links={analysis.links} onOpenUrl={previews?.browser ? onOpenUrl : null} />}
          {view === 'attachments' && (
            <MailAttachments
              attachments={analysis.attachments}
              sha256={message.sha256}
              onDownload={onDownload}
              onSend={onSend}
              sending={sending}
              onOpen={onOpen}
              previews={previews}
            />
          )}
          {detail.incidents?.length > 1 && (
            <p className="font-mono text-[11px] text-fg-muted">
              Also in{' '}
              {detail.incidents
                .filter((i) => i.id !== incident.id)
                .map((i) => i.name)
                .join(', ')}
            </p>
          )}
        </div>
      )}
    </Card>
  )
}
