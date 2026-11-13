import { useCallback, useEffect, useState } from 'react'
import { AlertCircle, HardDrive, RefreshCw } from 'lucide-react'
import { api } from '../../../services/api.js'
import { formatBytes } from '../../../domain/events.js'
import { formatRelative } from '../../../lib/time.js'
import { Button, MicroSkull, StatCard } from '../../ui/index.js'

/*
 * Storage settings section (admin only): the disk that holds Nik's files,
 * how full it is, and how Nik's own files share the used part. The largest
 * objects are listed, since those are what to delete when room is needed.
 */

const COLOURS = {
  mailboxes: '#58a6ff',
  captures: '#d2a8ff',
  samples: '#f85149',
  mails: '#e3b341',
  previews: '#3fb950',
  urls: '#79c0ff',
  rules: '#ffa657',
  database: '#ff9bce',
  other: '#8b949e',
}
const ELSEWHERE = '#484f58'
const GROUP_NAMES = { mailboxes: 'Mailbox', captures: 'Packet capture', samples: 'File', mails: 'E-mail' }

const share = (bytes, total) => (total > 0 ? (bytes / total) * 100 : 0)
const percent = (bytes, total) => {
  const value = share(bytes, total)
  if (value <= 0) return '—'
  return value < 0.1 ? '<0.1%' : `${value.toFixed(1)}%`
}

export default function StorageSection({ onOpenArtifact }) {
  const [usage, setUsage] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setUsage(await api.get('/storage'))
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  if (error && !usage) {
    return (
      <p role="alert" className="flex items-center gap-2 text-sm text-high">
        <AlertCircle className="h-4 w-4" aria-hidden="true" /> {error}
      </p>
    )
  }
  if (!usage) {
    return (
      <p className="flex items-center gap-2 text-sm text-fg-muted">
        <MicroSkull className="h-4 w-4" /> Measuring the disk…
      </p>
    )
  }

  const { disk, groups, largest, limits } = usage
  const full = share(disk.used, disk.total)
  const tone = full >= 90 ? 'danger' : full >= 75 ? 'warn' : 'ok'
  const segments = [
    ...groups.filter((group) => group.bytes > 0).map((group) => ({ ...group, colour: COLOURS[group.id] })),
    { id: 'elsewhere', label: 'Everything else on the disk', bytes: usage.elsewhere, colour: ELSEWHERE },
  ]

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <p className="max-w-2xl text-sm text-fg-muted">
          The disk that holds the files Nik keeps (samples, e-mails, packet captures, mailboxes). The database is
          counted as on this disk, as it is with the compose file Nik ships with.
        </p>
        <Button variant="ghost" onClick={load} disabled={loading}>
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" /> Measure again
        </Button>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <StatCard
          icon={HardDrive}
          label="Free"
          value={formatBytes(disk.free)}
          tone={tone}
          hint={`of ${formatBytes(disk.total)}`}
        />
        <StatCard label="Used" value={formatBytes(disk.used)} hint={`${full.toFixed(1)}% of the disk`} />
        <StatCard
          label="Used by Nik"
          value={formatBytes(usage.nik)}
          hint={`${percent(usage.nik, disk.total)} of the disk`}
        />
      </div>

      {full >= 90 && (
        <div role="alert" className="border-l-2 border-high-line bg-high-soft/50 px-3 py-2 text-sm">
          <b>The disk is almost full.</b> Uploads and analyses fail when no room is left: delete the largest objects
          below, or give the server more disk.
        </div>
      )}

      <section className="space-y-2">
        <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">How the disk is used</h3>
        <div
          role="img"
          aria-label={`${full.toFixed(1)}% of the disk is used, ${formatBytes(disk.free)} free`}
          className="flex h-4 w-full overflow-hidden border border-line bg-canvas"
        >
          {segments.map((segment) => (
            <i
              key={segment.id}
              title={`${segment.label}: ${formatBytes(segment.bytes)}`}
              className="block h-full"
              style={{ width: `${share(segment.bytes, disk.total)}%`, background: segment.colour }}
            />
          ))}
        </div>
        <table aria-label="Disk use" className="w-full text-sm">
          <thead>
            <tr className="border-b border-line text-left font-mono text-[11px] uppercase tracking-wider text-fg-muted">
              <th className="py-1.5 font-normal">What</th>
              <th className="py-1.5 text-right font-normal">Files</th>
              <th className="py-1.5 text-right font-normal">Size</th>
              <th className="py-1.5 text-right font-normal">Of the disk</th>
            </tr>
          </thead>
          <tbody>
            {groups.map((group) => (
              <tr key={group.id} className="border-b border-line-soft align-top">
                <td className="py-1.5">
                  <span className="flex items-center gap-2">
                    <i className="h-2.5 w-2.5 shrink-0" style={{ background: COLOURS[group.id] }} aria-hidden="true" />
                    {group.label}
                  </span>
                  <span className="block pl-[1.125rem] text-xs text-fg-muted">{group.about}</span>
                </td>
                <td className="py-1.5 text-right font-mono tabular-nums text-fg-muted">
                  {group.id === 'database' ? '' : group.files}
                </td>
                <td className="py-1.5 text-right font-mono tabular-nums">{formatBytes(group.bytes)}</td>
                <td className="py-1.5 text-right font-mono tabular-nums text-fg-muted">
                  {percent(group.bytes, disk.total)}
                </td>
              </tr>
            ))}
            <tr className="border-b border-line-soft align-top">
              <td className="py-1.5">
                <span className="flex items-center gap-2">
                  <i className="h-2.5 w-2.5 shrink-0" style={{ background: ELSEWHERE }} aria-hidden="true" />
                  Everything else on the disk
                </span>
                <span className="block pl-[1.125rem] text-xs text-fg-muted">
                  The system, container images, other software: not Nik's to delete.
                </span>
              </td>
              <td />
              <td className="py-1.5 text-right font-mono tabular-nums">{formatBytes(usage.elsewhere)}</td>
              <td className="py-1.5 text-right font-mono tabular-nums text-fg-muted">
                {percent(usage.elsewhere, disk.total)}
              </td>
            </tr>
            <tr className="align-top">
              <td className="py-1.5">
                <span className="flex items-center gap-2">
                  <i className="h-2.5 w-2.5 shrink-0 border border-line" aria-hidden="true" />
                  Free
                </span>
              </td>
              <td />
              <td className="py-1.5 text-right font-mono tabular-nums">{formatBytes(disk.free)}</td>
              <td className="py-1.5 text-right font-mono tabular-nums text-fg-muted">
                {percent(disk.free, disk.total)}
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <section className="space-y-2">
        <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">Largest objects</h3>
        {largest.length === 0 ? (
          <p className="text-sm text-fg-muted">Nothing is stored yet.</p>
        ) : (
          <ul aria-label="Largest objects" className="divide-y divide-line-soft border border-line">
            {largest.map((item) => (
              <li key={`${item.group}-${item.name}`} className="flex items-center gap-3 px-3 py-1.5 text-sm">
                <span className="w-28 shrink-0 text-xs text-fg-muted">{GROUP_NAMES[item.group]}</span>
                {item.artifactId && onOpenArtifact ? (
                  <button
                    type="button"
                    onClick={() => onOpenArtifact(item.artifactId)}
                    title="Open it: it can be deleted from its page"
                    className="min-w-0 flex-1 truncate text-left font-mono text-xs text-accent-fg hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    {item.name}
                  </button>
                ) : (
                  <span className="min-w-0 flex-1 truncate font-mono text-xs">{item.name}</span>
                )}
                {item.createdAt && (
                  <span className="hidden shrink-0 text-xs text-fg-muted sm:inline">
                    {formatRelative(item.createdAt)}
                  </span>
                )}
                <span className="w-20 shrink-0 text-right font-mono text-xs tabular-nums">
                  {formatBytes(item.bytes)}
                </span>
              </li>
            ))}
          </ul>
        )}
        <p className="text-xs text-fg-muted">
          An upload can be as large as {limits.mailboxMb} MB for a mailbox, {limits.pstMb} MB for a PST and{' '}
          {limits.pcapMb} MB for a packet capture.
        </p>
      </section>
    </div>
  )
}
