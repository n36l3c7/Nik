import { useState } from 'react'
import { Badge } from '../ui/index.js'
import { formatBytes } from '../../domain/events.js'
import {
  abuseReports,
  commandOf,
  cutNote,
  genericFacts,
  networkRange,
  otxPulses,
  otxValidation,
  safeBrowsingMatches,
  sourceOf,
  threatfoxIocs,
  toMs,
  urlhausPayloads,
  urlhausUrls,
  urlscanScans,
  vtEngines,
} from '../../domain/sourceDetails.js'
import { formatDate, formatDateTime } from '../../lib/time.js'

/*
 * What each source of threat intelligence says about an indicator, laid out
 * like the source's own page: the figures first, then the lists (engines,
 * reports, pulses, ports…). `data` is the outputs of the reputation command
 * of the source's connector, as the command gives them; what is shown of each
 * (how many rows, dates, names of categories) is shaped in
 * domain/sourceDetails.js. A connector this page has no layout for is shown as
 * plain rows.
 *
 * Nothing here is a link to the indicator itself or to what a source
 * returned about it: values are text, so a click never visits a hostile
 * address. Links go to the sources' own pages only.
 */

const when = (value) => {
  const ms = toMs(value)
  return ms ? formatDateTime(ms) : null
}
const day = (value) => {
  const ms = toMs(value)
  return ms ? formatDate(ms) : null
}
const yesNo = (value) => (value === undefined || value === null ? null : value ? 'yes' : 'no')
const joined = (value, limit = 20) => (Array.isArray(value) && value.length ? value.slice(0, limit).join(', ') : null)

function Section({ title, children }) {
  return (
    <section className="min-w-0 space-y-1.5">
      <h4 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">{title}</h4>
      {children}
    </section>
  )
}

/** Label / value pairs; rows without a value are left out. */
function Facts({ rows }) {
  const shown = rows.filter(([, value]) => value !== null && value !== undefined && value !== '')
  if (!shown.length) return null
  return (
    <dl className="grid grid-cols-[8.5rem_minmax(0,1fr)] gap-x-3 gap-y-0.5 font-mono text-xs">
      {shown.map(([label, value, tone]) => (
        <div key={label} className="contents">
          <dt className="text-fg-muted">{label}</dt>
          <dd className={`min-w-0 break-words ${tone ?? 'text-fg'}`}>{value}</dd>
        </div>
      ))}
    </dl>
  )
}

function Tags({ items, color = 'slate' }) {
  if (!Array.isArray(items) || !items.length) return null
  return (
    <span className="flex flex-wrap gap-1">
      {items.map((item) => (
        <Badge key={String(item)} color={color}>
          {String(item)}
        </Badge>
      ))}
    </span>
  )
}

/** A small table; `columns`: [{ label, render, className }]. */
function Table({ columns, rows, label }) {
  if (!rows?.length) return null
  return (
    <div className="overflow-x-auto">
      <table aria-label={label} className="w-full min-w-[26rem] border-collapse font-mono text-xs">
        <thead>
          <tr className="border-b border-line text-left text-fg-muted">
            {columns.map((c) => (
              <th key={c.label} className={`py-1 pr-3 font-normal ${c.className ?? ''}`}>
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className="border-b border-line-soft align-top">
              {columns.map((c) => (
                <td key={c.label} className={`break-words py-1 pr-3 text-fg ${c.className ?? ''}`}>
                  {c.render(row) ?? <span className="text-fg-subtle">—</span>}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** A ring filled to `percent`, with a figure in the middle (detection ratio, confidence). */
function Gauge({ percent, text, tone = 'high' }) {
  const colour = { high: 'var(--color-high-line)', med: 'var(--color-med-line)', ok: 'var(--color-accent)' }[tone]
  return (
    <div
      role="img"
      aria-label={text}
      className="grid h-[4.75rem] w-[4.75rem] shrink-0 place-items-center rounded-full"
      style={{
        background: `conic-gradient(${colour} ${Math.max(0, Math.min(100, percent))}%, var(--color-line-soft) 0)`,
      }}
    >
      <div className="grid h-[3.6rem] w-[3.6rem] place-items-center rounded-full bg-panel font-mono text-sm font-extrabold text-fg">
        {text}
      </div>
    </div>
  )
}

const Split = ({ children }) => <div className="grid gap-x-6 gap-y-4 md:grid-cols-2">{children}</div>
const Nothing = ({ children }) => <p className="font-mono text-xs text-fg-muted">{children}</p>
const sourceLink = (href, label) =>
  href ? (
    <a href={href} target="_blank" rel="noopener noreferrer" className="text-link hover:underline">
      {label}
    </a>
  ) : (
    label
  )

function VirusTotal({ data }) {
  // The command gives both lists: the vendors that flag the value, and all of them. Which is shown is
  // a choice of whoever reads the page.
  const [all, setAll] = useState(false)
  const stats = data.stats ?? {}
  const total = data.total ?? 0
  const flagged = (stats.malicious ?? 0) + (stats.suspicious ?? 0)
  const engines = vtEngines(data, all)
  const hasAll = Array.isArray(data.all_engines) && data.all_engines.length > 0
  const engineColour = { malicious: 'text-high', suspicious: 'text-med' }
  if (!total && !engines.length) return <Nothing>VirusTotal does not know this value.</Nothing>
  return (
    <>
      <Split>
        <Section title="Detection">
          <div className="flex items-center gap-3">
            <Gauge
              percent={total ? (flagged / total) * 100 : 0}
              text={`${stats.malicious ?? 0}/${total}`}
              tone={stats.malicious ? 'high' : stats.suspicious ? 'med' : 'ok'}
            />
            <Facts
              rows={[
                ['malicious', stats.malicious, 'text-high'],
                ['suspicious', stats.suspicious, 'text-med'],
                ['harmless', stats.harmless],
                ['undetected', stats.undetected],
                ['reputation', data.reputation],
              ]}
            />
          </div>
        </Section>
        <Section title="Details">
          <Facts
            rows={[
              ['threat label', data.label, 'text-high'],
              ['name', data.name],
              ['type', data.type],
              ['size', data.size ? formatBytes(data.size) : null],
              ['signer', data.signer],
              ['AS', data.asn || data.owner ? `${data.asn ? `AS${data.asn} ` : ''}${data.owner ?? ''}` : null],
              ['network', data.network],
              ['country', data.country],
              ['registrar', data.registrar],
              ['created', when(data.created)],
              ['title', data.title],
              ['final URL', data.final_url],
              ['HTTP status', data.http_status],
              ['first seen', when(data.first_seen)],
              ['last seen', when(data.last_seen)],
              ['last analysis', when(data.last_analysis)],
            ]}
          />
          <Tags items={[...(data.tags ?? []), ...(data.categories ?? [])]} />
        </Section>
      </Split>
      {data.names?.length > 1 && (
        <Section title="Known file names">
          <p className="break-words font-mono text-xs text-fg">{data.names.join(' · ')}</p>
        </Section>
      )}
      <Section
        title={
          all ? `Security vendors · ${engines.length}` : `Security vendors that flag it · ${engines.length} of ${total}`
        }
      >
        {hasAll && (
          <label className="flex items-center gap-2 text-xs text-fg-muted">
            <input
              type="checkbox"
              checked={all}
              onChange={(event) => setAll(event.target.checked)}
              className="h-3.5 w-3.5 accent-accent"
            />
            List every vendor
          </label>
        )}
        {engines.length ? (
          <ul aria-label="Security vendors" className="grid gap-x-5 font-mono text-xs sm:grid-cols-2 xl:grid-cols-3">
            {engines.map((e) => (
              <li key={e.engine} className="flex justify-between gap-2 border-b border-line-soft py-0.5">
                <span className="truncate text-fg">{e.engine}</span>
                <span className={`truncate ${engineColour[e.category] ?? 'text-fg-muted'}`}>
                  {e.result || e.category}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <Nothing>No vendor flags it.</Nothing>
        )}
      </Section>
    </>
  )
}

function AbuseIpdb({ data }) {
  const score = Number(data.score ?? 0)
  const reports = abuseReports(data.reports)
  return (
    <>
      <Split>
        <Section title="Abuse confidence">
          <div className="flex items-center gap-3">
            <Gauge percent={score} text={`${score}%`} tone={score >= 75 ? 'high' : score >= 25 ? 'med' : 'ok'} />
            <Facts
              rows={[
                ['reports', data.total_reports !== undefined ? `${data.total_reports ?? 0}` : null],
                ['reporters', data.distinct_users ? `${data.distinct_users} distinct` : null],
                ['last report', when(data.last_reported)],
              ]}
            />
          </div>
        </Section>
        <Section title="Details">
          <Facts
            rows={[
              ['ISP', data.isp],
              ['usage', data.usage_type],
              ['domain', data.domain],
              ['hostnames', joined(data.hostnames, 5)],
              ['country', data.country],
              ['Tor node', yesNo(data.is_tor)],
              ['whitelisted', yesNo(data.is_whitelisted)],
            ]}
          />
        </Section>
      </Split>
      {reports.length > 0 && (
        <Section title="Latest reports">
          <Table
            label="Abuse reports"
            rows={reports}
            columns={[
              {
                label: 'When',
                render: (r) => (r.date ? formatDateTime(r.date) : null),
                className: 'whitespace-nowrap',
              },
              { label: 'Categories', render: (r) => r.categories.join(' · ') },
              { label: 'Comment', render: (r) => r.comment },
              { label: 'From', render: (r) => r.country },
            ]}
          />
        </Section>
      )}
    </>
  )
}

function GreyNoise({ data }) {
  if (data.known === false) return <Nothing>GreyNoise has not seen this address scan the internet.</Nothing>
  const name = data.name && data.name !== 'unknown' ? data.name : null
  return (
    <Facts
      rows={[
        ['classification', data.classification, data.classification === 'malicious' ? 'text-high' : undefined],
        ['noise', data.noise ? 'yes: it scans the internet' : 'no'],
        ['RIOT', data.riot ? 'yes: a common business service' : 'no'],
        ['name', name],
        ['last seen', day(data.last_seen)],
      ]}
    />
  )
}

function Otx({ data }) {
  const pulses = otxPulses(data.pulse_details)
  return (
    <>
      <Facts
        rows={[
          ['pulses', data.pulse_count ?? 0],
          ['AS', data.asn],
          ['country', data.country],
          ['validation', otxValidation(data.validation).join(', ')],
        ]}
      />
      {data.families?.length > 0 && (
        <Section title="Malware families">
          <Tags items={data.families} color="red" />
        </Section>
      )}
      {pulses.length > 0 && (
        <Section title={`Pulses · ${pulses.length} of ${data.pulse_count ?? pulses.length}`}>
          <Table
            label="OTX pulses"
            rows={pulses}
            columns={[
              { label: 'Pulse', render: (p) => sourceLink(p.link, p.name) },
              { label: 'Author', render: (p) => p.author },
              {
                label: 'Modified',
                render: (p) => (p.modified ? formatDateTime(p.modified) : null),
                className: 'whitespace-nowrap',
              },
              { label: 'Tags', render: (p) => p.tags.join(', ') },
            ]}
          />
        </Section>
      )}
    </>
  )
}

function ThreatFox({ data }) {
  const iocs = threatfoxIocs(data.iocs)
  if (!iocs.length) return <Nothing>Not in ThreatFox.</Nothing>
  return (
    <Section title={`Indicators · ${iocs.length} of ${data.count ?? iocs.length}`}>
      <Table
        label="ThreatFox indicators"
        rows={iocs}
        columns={[
          { label: 'IOC', render: (e) => sourceLink(e.link, e.ioc), className: 'break-all' },
          { label: 'Malware', render: (e) => e.malware },
          { label: 'Threat', render: (e) => e.threat },
          { label: 'Confidence', render: (e) => (e.confidence !== null ? `${e.confidence}%` : null) },
          {
            label: 'First seen',
            render: (e) => (e.firstSeen ? formatDateTime(e.firstSeen) : null),
            className: 'whitespace-nowrap',
          },
        ]}
      />
    </Section>
  )
}

function UrlHaus({ data }) {
  if (data.query_status && data.query_status !== 'ok') return <Nothing>Not in URLhaus.</Nothing>
  const command = commandOf(data)
  const urls = urlhausUrls(data.urls)
  const urlTable = (
    <Table
      label="URLhaus URLs"
      rows={urls}
      columns={[
        { label: 'URL', render: (u) => u.url, className: 'break-all' },
        { label: 'Status', render: (u) => u.status },
        { label: 'Threat', render: (u) => u.threat },
        { label: 'Added', render: (u) => (u.added ? formatDateTime(u.added) : null), className: 'whitespace-nowrap' },
      ]}
    />
  )
  if (command === 'get-host-report')
    return Number(data.url_count) > 0 ? (
      <Section title={`${data.url_count} malware URLs on this host`}>
        <Facts rows={[['first seen', when(data.firstseen)]]} />
        {urlTable}
      </Section>
    ) : (
      <Nothing>URLhaus knows no malware URL on this host.</Nothing>
    )
  if (command === 'get-file-report')
    return (
      <Section title="Payload">
        <Facts
          rows={[
            ['signature', data.signature, 'text-high'],
            ['file type', data.file_type],
            ['size', data.file_size ? formatBytes(Number(data.file_size)) : null],
            ['first seen', when(data.firstseen)],
            ['last seen', when(data.lastseen)],
            ['served by', data.url_count ? `${data.url_count} URLs` : null],
          ]}
        />
        {urlTable}
      </Section>
    )
  return (
    <Section title="URL">
      <Facts
        rows={[
          ['status', data.url_status, data.url_status === 'online' ? 'text-high' : undefined],
          ['threat', data.threat],
          ['added', when(data.date_added)],
          ['last online', when(data.last_online)],
          ['reporter', data.reporter],
        ]}
      />
      <Tags items={data.tags} />
      <Table
        label="URLhaus payloads"
        rows={urlhausPayloads(data.payloads)}
        columns={[
          { label: 'Payload SHA-256', render: (p) => p.sha256, className: 'break-all' },
          { label: 'Type', render: (p) => p.fileType },
          { label: 'Signature', render: (p) => p.signature },
          { label: 'First seen', render: (p) => (p.firstSeen ? formatDateTime(p.firstSeen) : null) },
        ]}
      />
    </Section>
  )
}

function MalwareBazaar({ data }) {
  if (!data.sha256 && !data.signature) return <Nothing>Not in MalwareBazaar.</Nothing>
  return (
    <Section title="Sample">
      <Facts
        rows={[
          ['signature', data.signature, 'text-high'],
          ['file name', data.file_name],
          ['file type', data.file_type],
          ['size', data.file_size ? formatBytes(Number(data.file_size)) : null],
          ['delivery', data.delivery_method],
          ['first seen', when(data.first_seen)],
          ['last seen', when(data.last_seen)],
          ['reporter', data.reporter],
        ]}
      />
      <Tags items={Array.isArray(data.tags) ? data.tags.slice(0, 8) : []} />
    </Section>
  )
}

function Shodan({ data }) {
  const ports = Array.isArray(data.ports) ? data.ports.slice(0, 100) : []
  const vulns = Array.isArray(data.vulns) ? data.vulns : []
  const empty = !ports.length && !vulns.length && !data.hostnames?.length
  if (empty) return <Nothing>Shodan knows no open port on this address.</Nothing>
  return (
    <Split>
      <Section title="Open ports">
        <Tags items={ports.map((port) => `${port}/tcp`)} color="cyan" />
        <Facts
          rows={[
            ['hostnames', joined(data.hostnames, 10)],
            ['software', joined(data.cpes, 20)],
          ]}
        />
        <Tags items={Array.isArray(data.tags) ? data.tags.slice(0, 20) : []} color="amber" />
      </Section>
      <Section title={`Vulnerabilities · ${vulns.length}`}>
        {vulns.length ? (
          <p className="break-words font-mono text-xs text-fg">
            {vulns.slice(0, 50).join(' · ')}
            {vulns.length > 50 ? ` · and ${vulns.length - 50} more` : ''}
          </p>
        ) : (
          <Nothing>None known.</Nothing>
        )}
      </Section>
    </Split>
  )
}

function UrlScan({ data }) {
  const scans = urlscanScans(data.scans)
  if (!scans.length) return <Nothing>No public scan on urlscan.io. Nik submits nothing.</Nothing>
  return (
    <Section title={`Public scans · ${scans.length} of ${data.total ?? scans.length}`}>
      <Table
        label="urlscan.io scans"
        rows={scans}
        columns={[
          {
            label: 'Scanned',
            className: 'whitespace-nowrap',
            render: (s) => sourceLink(s.result, s.time ? formatDateTime(s.time) : 'open'),
          },
          { label: 'URL', render: (s) => s.url, className: 'break-all' },
          { label: 'Title', render: (s) => s.title },
          { label: 'Address', render: (s) => [s.ip, s.country].filter(Boolean).join(' · ') },
          {
            label: 'Verdict',
            render: (s) => (s.malicious ? <span className="text-high">malicious</span> : 'no verdict'),
          },
        ]}
      />
    </Section>
  )
}

function SafeBrowsing({ data }) {
  const matches = safeBrowsingMatches(data.matches)
  if (!matches.length) return <Nothing>Not on Google Safe Browsing&apos;s lists.</Nothing>
  return (
    <Table
      label="Safe Browsing matches"
      rows={matches}
      columns={[
        { label: 'Threat', render: (m) => <span className="text-high">{m.threat}</span> },
        { label: 'Platform', render: (m) => m.platform },
        { label: 'URL', render: (m) => m.url, className: 'break-all' },
      ]}
    />
  )
}

/** Registration data, read from the registries over RDAP. */
function Rdap({ data, verdict }) {
  if (commandOf(data) === 'get-ip')
    return data.name || data.handle || data.start_address ? (
      <Section title="Network">
        <Facts
          rows={[
            ['network', networkRange(data)],
            ['name', data.name],
            ['handle', data.handle],
            ['holder', data.holder],
            ['country', data.country],
            ['type', data.type],
            ['registered', day(data.registered)],
            ['last changed', day(data.changed)],
            ['abuse contact', data.abuse_email ?? data.holder_abuse_email],
          ]}
        />
      </Section>
    ) : (
      <Nothing>The registry has no record of this address.</Nothing>
    )
  if (!data.name) return <Nothing>The registry has no record of this domain.</Nothing>
  const age = typeof data.age_days === 'number' ? data.age_days : null
  const young = age !== null && verdict === 'suspicious'
  const steps = [
    ['registered', data.registered],
    ['last changed', data.changed],
    ['expires', data.expires],
  ].filter(([, at]) => day(at))
  return (
    <>
      {young && (
        <p role="alert" className="border-l-2 border-high-line bg-high-soft/50 px-3 py-2 text-sm text-fg">
          <b>
            Registered {age} {age === 1 ? 'day' : 'days'} ago.
          </b>{' '}
          A domain this young is a common sign of phishing and malware delivery: it counts in the score.
        </p>
      )}
      <ol aria-label="Registration dates" className="flex flex-wrap gap-x-6 gap-y-2 font-mono text-xs">
        {steps.map(([label, at]) => (
          <li key={label} className="border-t-2 border-line pt-1.5">
            <b className="block text-fg">{day(at)}</b>
            <span className="text-fg-muted">{label}</span>
          </li>
        ))}
        {age !== null && (
          <li className={`border-t-2 pt-1.5 ${young ? 'border-high-line' : 'border-line'}`}>
            <b className={`block ${young ? 'text-high' : 'text-fg'}`}>
              {age < 730 ? `${age} days` : `${Math.floor(age / 365)} years`}
            </b>
            <span className="text-fg-muted">age</span>
          </li>
        )}
      </ol>
      <Section title="Registration">
        <Facts
          rows={[
            [
              'domain',
              data.unicode_name && data.unicode_name !== data.name ? `${data.unicode_name} (${data.name})` : data.name,
            ],
            [
              'registrar',
              [data.registrar, data.registrar_id && `IANA ${data.registrar_id}`].filter(Boolean).join(' · '),
            ],
            ['registrant', data.registrant],
            ['name servers', joined(data.nameservers)],
            ['status', joined(data.status)],
            ['DNSSEC', data.dnssec],
            ['abuse contact', data.abuse_email],
          ]}
        />
      </Section>
    </>
  )
}

/** A connector this page has no layout for: its outputs, as they are named in its file. */
function Generic({ data }) {
  const rows = genericFacts(data)
  if (!rows.length) return null
  return <Facts rows={rows} />
}

const VIEWS = {
  rdap: Rdap,
  virustotal: VirusTotal,
  abuseipdb: AbuseIpdb,
  greynoise: GreyNoise,
  otx: Otx,
  threatfox: ThreatFox,
  urlhaus: UrlHaus,
  malwarebazaar: MalwareBazaar,
  shodan: Shodan,
  urlscan: UrlScan,
  safebrowsing: SafeBrowsing,
}

/** The body of a source's card: the details of its answer. */
export default function SourceDetails({ data, verdict }) {
  const held = data ?? {}
  const View = VIEWS[sourceOf(held)] ?? Generic
  const note = cutNote(held)
  return (
    <div className="space-y-4">
      <View data={held} verdict={verdict} />
      {note && <p className="font-mono text-[11px] text-fg-muted">{note}</p>}
    </div>
  )
}
