import { useCallback, useEffect, useState } from 'react'
import { AlertCircle, HardDrive, Lock, Pause, Play, RefreshCw, ScanSearch } from 'lucide-react'
import { api } from '../../../services/api.js'
import { formatBytes } from '../../../domain/events.js'
import { formatRelative } from '../../../lib/time.js'
import { formatDateTime } from '../../../lib/time.js'
import { Badge, Button, StatCard, TransferBar, Wait } from '../../ui/index.js'
import { expiryText, undatedText } from '../../../domain/artifactExpiry.js'
import { encryptionStatus } from '../../../domain/keys.js'

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

/**
 * The encryption of the store: whether every file is sealed and since when; while the files of a
 * server from before 6.8 are being sealed, how far that is, with its pause; the files found damaged.
 */
function Encryption() {
  const [status, setStatus] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async (background = false) => {
    try {
      setStatus(await api.get('/storage/encryption', background ? { background: true } : undefined))
      setError(null)
    } catch (failure) {
      setError(failure.message)
    }
  }, [])
  useEffect(() => {
    load()
  }, [load])

  const shown = status ? encryptionStatus(status, formatBytes, (iso) => formatDateTime(Date.parse(iso))) : null
  // While the server works the panel is read again, so the bar follows it to its end.
  const working = Boolean(shown?.working)
  useEffect(() => {
    if (!working) return undefined
    const timer = setInterval(() => load(true), 3000)
    return () => clearInterval(timer)
  }, [working, load])

  const act = async (action) => {
    setBusy(true)
    try {
      setStatus(await api.post('/storage/encryption', { action }))
      setError(null)
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  if (!status && !error) return <Wait>Reading the encryption of the store…</Wait>
  const stuck = status?.stuck ?? []
  const damaged = status?.damaged ?? []
  return (
    <section aria-label="Encryption of the store" className="space-y-2 border border-line bg-panel px-3 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <Lock className="h-4 w-4 text-accent" aria-hidden="true" />
        <h3 className="text-sm font-medium text-fg">Encryption of the store</h3>
        {shown && <Badge color={shown.color}>{shown.title}</Badge>}
        {status?.keyFingerprint && (
          <span className="text-xs text-fg-muted">
            store key <span className="font-mono text-fg">{status.keyFingerprint}</span>
          </span>
        )}
        <span className="ml-auto flex gap-2">
          {status?.state === 'converting' && (
            <Button
              variant="secondary"
              size="sm"
              icon={Pause}
              waiting={busy}
              disabled={busy}
              onClick={() => act('pause')}
            >
              Pause
            </Button>
          )}
          {status?.state === 'paused' && (
            <Button
              variant="secondary"
              size="sm"
              icon={Play}
              waiting={busy}
              disabled={busy}
              onClick={() => act('resume')}
            >
              Go on
            </Button>
          )}
          {status?.state === 'sealed' && (
            <Button
              variant="ghost"
              size="sm"
              icon={ScanSearch}
              waiting={busy}
              disabled={busy}
              onClick={() => act('check')}
              title="Walk the whole store again: a file found in clear is encrypted"
            >
              Check again
            </Button>
          )}
        </span>
      </div>
      {error && (
        <p role="alert" className="text-sm text-high">
          {error}
        </p>
      )}
      {shown && (
        <div role="status" className="space-y-1">
          {shown.lines.map((line) => (
            <p key={line} className="max-w-prose text-sm text-fg-muted">
              {line}
            </p>
          ))}
        </div>
      )}
      {shown?.percent != null && <TransferBar label="Encrypting the store of files" percent={shown.percent} />}
      {status && status.state !== 'sealed' && (
        <p className="max-w-prose text-xs text-fg-muted">
          Every file is read, encrypted beside itself, read back and compared before it takes the place of the one in
          clear: one at a time, so the room needed is that of the largest file. Nik is used as before meanwhile.
        </p>
      )}
      {stuck.length > 0 && (
        <ul
          aria-label="Files that could not be encrypted"
          className="divide-y divide-line-soft border border-high-line"
        >
          {stuck.map((item) => (
            <li key={item.name} className="px-3 py-1.5 text-xs">
              <span className="font-mono text-fg">{item.name}</span>
              <span className="block text-fg-muted">{item.reason}</span>
            </li>
          ))}
        </ul>
      )}
      {damaged.length > 0 && (
        <div className="space-y-1">
          <p role="alert" className="text-sm text-high">
            {damaged.length === 1
              ? 'A file of the store is damaged'
              : `${damaged.length} files of the store are damaged`}
            : what is on the disk is not what Nik wrote, and it is not served. Put it back from a backup.
          </p>
          <ul aria-label="Damaged files" className="divide-y divide-line-soft border border-high-line">
            {damaged.map((item) => (
              <li key={item.name} className="px-3 py-1.5 text-xs">
                <span className="font-mono text-fg">{item.name}</span>
                <span className="block text-fg-muted">
                  {formatDateTime(Date.parse(item.at))}: {item.reason}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  )
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
    return <Wait>Measuring the disk…</Wait>
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
        <Button variant="ghost" icon={RefreshCw} waiting={loading} onClick={load} disabled={loading}>
          {loading ? 'Measuring…' : 'Measure again'}
        </Button>
      </div>

      <Encryption />

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

      <section className="space-y-2">
        <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">With a date</h3>
        <p className="text-sm text-fg-muted">
          An artifact is deleted by itself only when someone gave it a date, on its page.{' '}
          {undatedText(usage.undated, formatBytes)}
        </p>
        {(usage.dated ?? []).length > 0 && (
          <ul aria-label="Artifacts with a date" className="divide-y divide-line-soft border border-line">
            {usage.dated.map((item) => (
              <li key={item.artifactId} className="flex flex-wrap items-center gap-x-3 gap-y-0.5 px-3 py-1.5 text-sm">
                <span className="w-28 shrink-0 text-xs text-fg-muted">{expiryText(item).replace(/ \(.*\)$/, '')}</span>
                {onOpenArtifact ? (
                  <button
                    type="button"
                    onClick={() => onOpenArtifact(item.artifactId)}
                    title="Open it: its date is changed on its page"
                    className="min-w-0 flex-1 truncate text-left font-mono text-xs text-accent-fg hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    {item.name}
                  </button>
                ) : (
                  <span className="min-w-0 flex-1 truncate font-mono text-xs">{item.name}</span>
                )}
                <span className="shrink-0 font-mono text-xs text-fg-muted">{item.expiresAt}</span>
                <span className="w-20 shrink-0 text-right font-mono text-xs tabular-nums">
                  {formatBytes(item.bytes)}
                </span>
                {item.expiryNote && <span className="w-full text-xs text-med">{item.expiryNote}.</span>}
              </li>
            ))}
          </ul>
        )}
        {usage.datedCount > (usage.dated ?? []).length && (
          <p className="text-xs text-fg-muted">
            The first {usage.dated.length} of {usage.datedCount}, the soonest first.
          </p>
        )}
      </section>
    </div>
  )
}
