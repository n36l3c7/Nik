import { useCallback, useEffect, useState } from 'react'
import { Link2, ShieldCheck } from 'lucide-react'
import { api } from '../../../services/api.js'
import { chainStatus, parseHead, shortHash } from '../../../domain/auditChain.js'
import { formatRelative } from '../../../lib/time.js'
import { Badge, Button, Wait } from '../../ui/index.js'

/*
 * The chain of the audit log: every entry carries the hash of the one before
 * it, so an entry that was changed, removed or moved shows when the chain is
 * walked. The server walks it by itself every few minutes; this panel says
 * where that stands and walks it on demand.
 *
 * The end of the log is the one thing a chain cannot vouch for alone: the
 * newest entries can be removed and what is left still holds together. A head
 * kept elsewhere tells (the last checkpoint a syslog receiver got): it can be
 * typed here and the log is held against it.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 font-mono text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

export default function AuditChainPanel({ onVerified }) {
  const [chain, setChain] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [said, setSaid] = useState(null)
  const [outside, setOutside] = useState('')
  const [full, setFull] = useState(false)

  const load = useCallback(async () => {
    try {
      setChain(await api.get('/audit/chain'))
      setError(null)
    } catch (failure) {
      setError(failure.message)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const head = parseHead(outside)
  const verify = async () => {
    if (head?.error) return
    setBusy(true)
    setSaid(null)
    try {
      const found = await api.post('/audit/chain/verify', { full, ...(head ? { head } : {}) })
      setChain(found)
      setError(null)
      setSaid(
        found.problem
          ? null
          : `The chain holds up to entry ${found.verified?.seq ?? 0}` +
              (head ? ', and the head you gave is in it.' : full ? ': every entry was read.' : '.'),
      )
      onVerified?.()
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  const status = chainStatus(chain, formatRelative)

  return (
    <section aria-label="Chain of the audit log" className="border border-line bg-panel p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Link2 className="h-4 w-4 text-accent" aria-hidden="true" />
            <h3 className="text-sm font-semibold text-fg">Chain</h3>
            {chain && <Badge color={status.color}>{status.text}</Badge>}
          </div>
          {!chain && !error && <Wait inline>Reading the state of the chain…</Wait>}
          {chain && (
            <p role="status" aria-label="State of the chain" className="mt-1 max-w-prose text-sm text-fg-muted">
              {status.detail}
            </p>
          )}
          {chain?.head?.seq > 0 && (
            <p className="mt-1 font-mono text-xs text-fg-muted">
              head {chain.head.seq}:{shortHash(chain.head.hash)} · signed with the key {chain.keyId}
              {chain.outside ? ` · ${chain.outside} written outside the server` : ''}
            </p>
          )}
        </div>
        <Button variant="secondary" size="sm" icon={ShieldCheck} waiting={busy} disabled={busy} onClick={verify}>
          Verify now
        </Button>
      </div>

      {chain?.problem && (
        <p role="alert" className="mt-3 border border-high-line bg-high-soft px-3 py-2 text-sm text-high">
          The log was changed outside Nik, or the database is damaged. Compare it with a copy that left the server: on
          the server, <span className="font-mono">python -m app.auditlog export</span> writes the entries, and{' '}
          <span className="font-mono">verifier.py</span> holds them against what the syslog receiver got.
        </p>
      )}
      {error && (
        <p role="alert" className="mt-3 border border-high-line bg-high-soft px-3 py-2 text-sm text-high">
          {error}
        </p>
      )}
      {said && (
        <p role="status" className="mt-3 text-sm text-accent-fg">
          {said}
        </p>
      )}

      <details className="mt-3 text-sm text-fg-muted">
        <summary className="cursor-pointer select-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent">
          Hold it against a head from outside
        </summary>
        <div className="mt-2 flex max-w-2xl flex-col gap-2">
          <p className="max-w-prose text-xs">
            A chain shows an entry that was changed, removed from the middle or moved. It cannot show by itself that the
            newest entries were removed, nor that the log was computed again from some point: for that the log is held
            against a head kept somewhere else. The syslog receiver gets one in every checkpoint (
            <span className="font-mono">seq</span> and <span className="font-mono">hash</span>).
          </p>
          <label className="flex flex-col gap-1" htmlFor="audit-outside-head">
            Head from outside
            <input
              id="audit-outside-head"
              type="text"
              value={outside}
              spellCheck={false}
              autoComplete="off"
              placeholder="4182:9f2c…  (the number of the entry, a colon, its hash)"
              onChange={(event) => setOutside(event.target.value)}
              className={INPUT}
            />
          </label>
          {head?.error && <p className="text-xs text-med-fg">{head.error}</p>}
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={full} onChange={(event) => setFull(event.target.checked)} />
            Read every entry, not only what was added since the last walk
          </label>
        </div>
      </details>
    </section>
  )
}
