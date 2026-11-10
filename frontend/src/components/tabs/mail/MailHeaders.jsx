import { useState } from 'react'
import { AlertTriangle, ArrowDown, ShieldCheck } from 'lucide-react'
import { Badge, SearchInput } from '../../ui/index.js'
import { IocValue } from '../../../context/IocLookupContext.jsx'
import { formatDateTime } from '../../../lib/time.js'
import { formatDelay, resultColor } from '../../../domain/mail.js'

/*
 * The headers made readable: the route the message took (the Received chain
 * from the sender to the mailbox, with delays and clocks going back), the
 * authentication as checked by Nik and as reported by the receiving servers
 * (only your own servers' reports can be believed: anyone can write such a
 * header), and every header in order, searchable.
 */

function Route({ route, originIp }) {
  if (!route.length) return <p className="font-mono text-xs text-fg-muted">No Received header.</p>
  return (
    <ol className="space-y-1 font-mono text-xs">
      {route.map((hop, i) => (
        <li key={i}>
          {i > 0 && (
            <div className="flex items-center gap-2 py-0.5 pl-3 text-fg-subtle">
              <ArrowDown className="h-3 w-3" aria-hidden="true" />
              {hop.delayMs !== null && (
                <span className={hop.backwards ? 'text-high' : ''}>
                  {formatDelay(hop.delayMs)}
                  {hop.backwards && ' · clock goes back'}
                </span>
              )}
            </div>
          )}
          <div
            className={[
              'grid gap-x-3 gap-y-0.5 border px-3 py-2 sm:grid-cols-[minmax(0,1fr)_auto]',
              hop.ip && hop.ip === originIp ? 'border-med-line bg-med-soft/40' : 'border-line',
            ].join(' ')}
          >
            <span className="min-w-0 break-all text-fg">
              <span className="text-fg-muted">from </span>
              {hop.from || '?'}
              {hop.ip && (
                <>
                  {' '}
                  [<IocValue type="ip" value={hop.ip} />]
                </>
              )}
              {hop.ip === originIp && (
                <Badge color="amber" className="ml-2">
                  sending server
                </Badge>
              )}
              {hop.privateIp && <Badge className="ml-2">private</Badge>}
            </span>
            <span className="text-fg-muted">{hop.time ? formatDateTime(hop.time) : '—'}</span>
            <span className="min-w-0 break-all text-fg-muted">
              by <span className="text-fg">{hop.by || '?'}</span>
              {hop.with && ` · ${hop.with}`}
            </span>
          </div>
        </li>
      ))}
    </ol>
  )
}

function AuthTable({ auth }) {
  const verified = auth.verified
  const rows = ['spf', 'dkim', 'dmarc']
  return (
    <div className="space-y-3">
      <table className="w-full table-fixed border-collapse font-mono text-xs">
        <thead>
          <tr className="border-b border-line text-left text-fg-muted">
            <th className="w-20 py-1.5 font-normal">check</th>
            <th className="py-1.5 font-normal">Nik, through DNS now</th>
            <th className="py-1.5 font-normal">receiving servers</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((method) => {
            const nik = verified?.[method]
            const reported = auth.reported.summary?.[method]
            return (
              <tr key={method} className="border-b border-line-soft align-top">
                <td className="py-2 uppercase text-fg">{method}</td>
                <td className="py-2 pr-3">
                  {nik ? (
                    <>
                      <Badge color={resultColor(nik.result)}>{nik.result}</Badge>
                      <span className="ml-2 break-words text-fg-muted">
                        {method === 'dkim' && nik.domain ? `d=${nik.domain} · ` : ''}
                        {method === 'dmarc' && nik.policy ? `p=${nik.policy} · ` : ''}
                        {nik.detail}
                      </span>
                    </>
                  ) : (
                    <span className="text-fg-subtle">
                      {method === 'dkim' && !auth.dkimVerifiable ? 'not verifiable on an Outlook .msg' : 'not checked'}
                    </span>
                  )}
                </td>
                <td className="py-2">
                  {reported ? (
                    <>
                      <Badge color={resultColor(reported.result)}>{reported.result}</Badge>
                      {reported.trusted ? (
                        <ShieldCheck className="ml-1 inline h-3.5 w-3.5 text-accent" aria-label="your server" />
                      ) : (
                        <span className="ml-2 text-fg-subtle">unverified header</span>
                      )}
                    </>
                  ) : (
                    <span className="text-fg-subtle">—</span>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
      {verified?.dkim?.signatures?.length > 1 && (
        <p className="font-mono text-xs text-fg-muted">
          DKIM signatures: {verified.dkim.signatures.map((s) => `${s.domain} (${s.selector}) ${s.result}`).join(' · ')}
        </p>
      )}
      {auth.reported.entries.length > 0 && !auth.reported.entries.some((e) => e.trusted) && (
        <p className="flex gap-2 font-mono text-xs text-med">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          None of the Authentication-Results headers comes from a server listed in Settings → Mail: they may have been
          written by the sender.
        </p>
      )}
    </div>
  )
}

export default function MailHeaders({ analysis }) {
  const [query, setQuery] = useState('')
  const needle = query.trim().toLowerCase()
  const headers = analysis.headers.filter(
    ([name, value]) => !needle || name.toLowerCase().includes(needle) || value.toLowerCase().includes(needle),
  )
  return (
    <div className="space-y-5">
      <section className="space-y-2">
        <h3 className="font-mono text-xs uppercase tracking-wider text-fg-muted">Authentication</h3>
        <AuthTable auth={analysis.auth} />
      </section>
      <section className="space-y-2">
        <h3 className="font-mono text-xs uppercase tracking-wider text-fg-muted">
          Route · {analysis.route.length} hop{analysis.route.length === 1 ? '' : 's'}, sender first
        </h3>
        <Route route={analysis.route} originIp={analysis.originIp} />
      </section>
      <section className="space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="font-mono text-xs uppercase tracking-wider text-fg-muted">
            All headers · {analysis.headers.length}
          </h3>
          <div className="w-64">
            <SearchInput value={query} onChange={setQuery} placeholder="Filter headers" />
          </div>
        </div>
        <dl className="grid max-h-[50vh] grid-cols-[minmax(8rem,14rem)_minmax(0,1fr)] gap-x-3 overflow-auto border border-line font-mono text-[11px]">
          {headers.map(([name, value], i) => (
            <div key={i} className="contents">
              <dt className="border-b border-line-soft px-2 py-1 text-fg-muted">{name}</dt>
              <dd className="break-all border-b border-line-soft px-2 py-1 text-fg">{value}</dd>
            </div>
          ))}
        </dl>
      </section>
    </div>
  )
}
