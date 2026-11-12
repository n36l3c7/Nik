import { Badge } from '../ui/index.js'
import { formatBytes } from '../../domain/events.js'
import { formatDateTime } from '../../lib/time.js'

/*
 * What each threat-intelligence provider says about an indicator, laid out
 * like the provider's own page: the figures first, then the lists (engines,
 * reports, pulses, ports…). `data` is the shape documented in
 * backend/app/enrichment/providers.py; every field may be missing.
 *
 * Nothing here is a link to the indicator itself or to what a provider
 * returned about it: values are text, so a click never visits a hostile
 * address. Links go to the providers' own pages only.
 */

const when = (ms) => (ms ? formatDateTime(ms) : null)
const yesNo = (value) => (value === undefined || value === null ? null : value ? 'yes' : 'no')

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
  if (!items?.length) return null
  return (
    <span className="flex flex-wrap gap-1">
      {items.map((item) => (
        <Badge key={item} color={color}>
          {item}
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
const ratio = (item) => (item.total ? `${item.malicious}/${item.total}` : null)

function VirusTotal({ data }) {
  const stats = data.stats ?? {}
  const flagged = (stats.malicious ?? 0) + (stats.suspicious ?? 0)
  const relations = data.relations ?? {}
  const engineColour = { malicious: 'text-high', suspicious: 'text-med' }
  return (
    <>
      <Split>
        <Section title="Detection">
          <div className="flex items-center gap-3">
            <Gauge
              percent={data.total ? (flagged / data.total) * 100 : 0}
              text={`${stats.malicious ?? 0}/${data.total ?? 0}`}
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
              ['final URL', data.finalUrl],
              ['HTTP status', data.httpStatus],
              ['first seen', when(data.firstSeen)],
              ['last seen', when(data.lastSeen)],
              ['last analysis', when(data.lastAnalysis)],
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
          data.enginesShown === 'all'
            ? `Security vendors · ${data.engines?.length ?? 0}`
            : `Security vendors that flag it · ${data.engines?.length ?? 0} of ${data.total ?? 0}`
        }
      >
        {data.engines?.length ? (
          <ul aria-label="Security vendors" className="grid gap-x-5 font-mono text-xs sm:grid-cols-2 xl:grid-cols-3">
            {data.engines.map((e) => (
              <li key={e.engine} className="flex justify-between gap-2 border-b border-line-soft py-0.5">
                <span className="truncate text-fg">{e.engine}</span>
                <span className={`truncate ${engineColour[e.category] ?? 'text-fg-muted'}`}>
                  {e.result || e.category}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="font-mono text-xs text-fg-muted">No vendor flags it.</p>
        )}
      </Section>
      {relations.resolutions?.length > 0 && (
        <Section title="Relations · passive DNS">
          <Table
            label="Passive DNS"
            rows={relations.resolutions}
            columns={[
              { label: 'Host', render: (r) => r.host },
              { label: 'Address', render: (r) => r.ip },
              { label: 'Seen', render: (r) => when(r.date) },
            ]}
          />
        </Section>
      )}
      {relations.communicating_files?.length > 0 && (
        <Section title="Relations · files that contact it">
          <Table
            label="Communicating files"
            rows={relations.communicating_files}
            columns={[
              { label: 'SHA-256', render: (r) => r.sha256, className: 'break-all' },
              { label: 'Name', render: (r) => r.name || r.type },
              { label: 'Detections', render: ratio },
            ]}
          />
        </Section>
      )}
      {relations.contacted_domains?.length > 0 && (
        <Section title="Relations · domains it contacts">
          <Table
            label="Contacted domains"
            rows={relations.contacted_domains}
            columns={[
              { label: 'Domain', render: (r) => r.domain },
              { label: 'Detections', render: ratio },
            ]}
          />
        </Section>
      )}
      {relations.contacted_ips?.length > 0 && (
        <Section title="Relations · addresses it contacts">
          <Table
            label="Contacted addresses"
            rows={relations.contacted_ips}
            columns={[
              { label: 'Address', render: (r) => r.ip },
              { label: 'Country', render: (r) => r.country },
              { label: 'Owner', render: (r) => r.owner },
            ]}
          />
        </Section>
      )}
      {data.comments?.length > 0 && (
        <Section title="Community comments">
          <ul className="space-y-2 font-mono text-xs">
            {data.comments.map((c, i) => (
              <li key={i} className="border-l-2 border-line pl-2">
                <span className="text-fg-muted">{when(c.date)}</span>
                <p className="whitespace-pre-wrap break-words text-fg">{c.text}</p>
              </li>
            ))}
          </ul>
        </Section>
      )}
      {data.skipped?.length > 0 && <p className="font-mono text-xs text-med">Not loaded: {data.skipped.join('; ')}.</p>}
    </>
  )
}

function AbuseIpdb({ data }) {
  return (
    <>
      <Split>
        <Section title="Abuse confidence">
          <div className="flex items-center gap-3">
            <Gauge
              percent={data.score ?? 0}
              text={`${data.score ?? 0}%`}
              tone={data.score >= 75 ? 'high' : data.score >= 25 ? 'med' : 'ok'}
            />
            <Facts
              rows={[
                ['reports', data.totalReports !== undefined ? `${data.totalReports ?? 0} in 90 days` : null],
                ['reporters', data.distinctUsers ? `${data.distinctUsers} distinct` : null],
                ['last report', when(data.lastReported)],
              ]}
            />
          </div>
        </Section>
        <Section title="Details">
          <Facts
            rows={[
              ['ISP', data.isp],
              ['usage', data.usage],
              ['domain', data.domain],
              ['hostnames', data.hostnames?.join(', ')],
              ['country', data.country],
              ['Tor node', yesNo(data.tor)],
              ['whitelisted', yesNo(data.whitelisted)],
            ]}
          />
        </Section>
      </Split>
      {data.reports?.length > 0 && (
        <Section title="Latest reports">
          <Table
            label="Abuse reports"
            rows={data.reports}
            columns={[
              { label: 'When', render: (r) => when(r.date), className: 'whitespace-nowrap' },
              { label: 'Categories', render: (r) => r.categories?.join(' · ') },
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
  if (data.known === false)
    return <p className="font-mono text-xs text-fg-muted">GreyNoise has not seen this address scan the internet.</p>
  return (
    <Facts
      rows={[
        ['classification', data.classification, data.classification === 'malicious' ? 'text-high' : undefined],
        ['noise', data.noise ? 'yes: it scans the internet' : 'no'],
        ['RIOT', data.riot ? 'yes: a common business service' : 'no'],
        ['name', data.name],
        ['last seen', when(data.lastSeen)],
      ]}
    />
  )
}

function Otx({ data }) {
  return (
    <>
      <Facts
        rows={[
          ['pulses', data.pulseCount ?? 0],
          ['AS', data.asn],
          ['country', data.country],
          ['validation', data.validation?.join(', ')],
        ]}
      />
      {data.families?.length > 0 && (
        <Section title="Malware families">
          <Tags items={data.families} color="red" />
        </Section>
      )}
      {data.pulses?.length > 0 && (
        <Section title={`Pulses · ${data.pulses.length} of ${data.pulseCount}`}>
          <Table
            label="OTX pulses"
            rows={data.pulses}
            columns={[
              {
                label: 'Pulse',
                render: (p) =>
                  p.link ? (
                    <a href={p.link} target="_blank" rel="noopener noreferrer" className="text-link hover:underline">
                      {p.name}
                    </a>
                  ) : (
                    p.name
                  ),
              },
              { label: 'Author', render: (p) => p.author },
              { label: 'Modified', render: (p) => when(p.modified), className: 'whitespace-nowrap' },
              { label: 'Tags', render: (p) => p.tags?.join(', ') },
            ]}
          />
        </Section>
      )}
    </>
  )
}

function AbuseCh({ data }) {
  const empty = !data.threatfox?.length && !data.sample && !data.urlhaus && !data.urlhausHost
  if (empty)
    return <p className="font-mono text-xs text-fg-muted">Not in ThreatFox, URLhaus or MalwareBazaar for this type.</p>
  return (
    <>
      {data.sample && (
        <Section title="MalwareBazaar · sample">
          <Facts
            rows={[
              ['signature', data.sample.signature, 'text-high'],
              ['file name', data.sample.fileName],
              ['file type', data.sample.fileType],
              ['size', data.sample.size ? formatBytes(data.sample.size) : null],
              ['delivery', data.sample.delivery],
              ['first seen', when(data.sample.firstSeen)],
              ['last seen', when(data.sample.lastSeen)],
              ['reporter', data.sample.reporter],
            ]}
          />
          <Tags items={data.sample.tags} />
        </Section>
      )}
      {data.urlhaus && (
        <Section title="URLhaus · URL">
          <Facts
            rows={[
              ['status', data.urlhaus.status, data.urlhaus.status === 'online' ? 'text-high' : undefined],
              ['threat', data.urlhaus.threat],
              ['added', when(data.urlhaus.dateAdded)],
              ['reporter', data.urlhaus.reporter],
            ]}
          />
          <Tags items={data.urlhaus.tags} />
          <Table
            label="URLhaus payloads"
            rows={data.urlhaus.payloads}
            columns={[
              { label: 'Payload SHA-256', render: (p) => p.sha256, className: 'break-all' },
              { label: 'Type', render: (p) => p.fileType },
              { label: 'Signature', render: (p) => p.signature },
              { label: 'First seen', render: (p) => when(p.firstSeen) },
            ]}
          />
        </Section>
      )}
      {data.urlhausHost && (
        <Section title={`URLhaus · ${data.urlhausHost.urlCount} malware URLs on this host`}>
          <Table
            label="URLhaus URLs"
            rows={data.urlhausHost.urls}
            columns={[
              { label: 'URL', render: (u) => u.url, className: 'break-all' },
              { label: 'Status', render: (u) => u.status },
              { label: 'Threat', render: (u) => u.threat },
              { label: 'Added', render: (u) => when(u.dateAdded), className: 'whitespace-nowrap' },
            ]}
          />
        </Section>
      )}
      {data.threatfox?.length > 0 && (
        <Section title="ThreatFox · indicators">
          <Table
            label="ThreatFox indicators"
            rows={data.threatfox}
            columns={[
              { label: 'IOC', render: (e) => e.ioc, className: 'break-all' },
              { label: 'Malware', render: (e) => e.malware },
              { label: 'Threat', render: (e) => e.threat },
              { label: 'Confidence', render: (e) => (e.confidence !== undefined ? `${e.confidence}%` : null) },
              { label: 'First seen', render: (e) => when(e.firstSeen), className: 'whitespace-nowrap' },
            ]}
          />
        </Section>
      )}
    </>
  )
}

function Shodan({ data }) {
  const empty = !data.ports?.length && !data.vulns?.length && !data.hostnames?.length
  if (empty) return <p className="font-mono text-xs text-fg-muted">Shodan knows no open port on this address.</p>
  return (
    <Split>
      <Section title="Open ports">
        <Tags items={(data.ports ?? []).map((port) => `${port}/tcp`)} color="cyan" />
        <Facts
          rows={[
            ['hostnames', data.hostnames?.join(', ')],
            ['software', data.cpes?.join(', ')],
          ]}
        />
        <Tags items={data.tags} color="amber" />
      </Section>
      <Section title={`Vulnerabilities · ${data.vulns?.length ?? 0}`}>
        {data.vulns?.length ? (
          <p className="break-words font-mono text-xs text-fg">{data.vulns.join(' · ')}</p>
        ) : (
          <p className="font-mono text-xs text-fg-muted">None known.</p>
        )}
      </Section>
    </Split>
  )
}

function UrlScan({ data }) {
  if (!data.scans?.length)
    return <p className="font-mono text-xs text-fg-muted">No public scan on urlscan.io. Nik submits nothing.</p>
  return (
    <Section title={`Public scans · ${data.scans.length} of ${data.total}`}>
      <Table
        label="urlscan.io scans"
        rows={data.scans}
        columns={[
          {
            label: 'Scanned',
            className: 'whitespace-nowrap',
            render: (s) =>
              s.result ? (
                <a href={s.result} target="_blank" rel="noopener noreferrer" className="text-link hover:underline">
                  {when(s.time) ?? 'open'}
                </a>
              ) : (
                when(s.time)
              ),
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
  if (!data.matches?.length)
    return <p className="font-mono text-xs text-fg-muted">Not on Google Safe Browsing&apos;s lists.</p>
  return (
    <Table
      label="Safe Browsing matches"
      rows={data.matches}
      columns={[
        { label: 'Threat', render: (m) => <span className="text-high">{m.threat}</span> },
        { label: 'Platform', render: (m) => m.platform },
        { label: 'URL', render: (m) => m.url, className: 'break-all' },
      ]}
    />
  )
}

const VIEWS = {
  virustotal: VirusTotal,
  abuseipdb: AbuseIpdb,
  greynoise: GreyNoise,
  otx: Otx,
  abusech: AbuseCh,
  internetdb: Shodan,
  urlscan: UrlScan,
  safebrowsing: SafeBrowsing,
}

/** The body of a provider's card. */
export default function SourceDetails({ provider, data }) {
  const View = VIEWS[provider]
  if (!View) return null
  return (
    <div className="space-y-4">
      <View data={data ?? {}} />
    </div>
  )
}
