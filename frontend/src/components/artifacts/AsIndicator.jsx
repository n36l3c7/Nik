import { useCallback, useEffect, useState } from 'react'
import { Radar } from 'lucide-react'
import { IocValue } from '../../context/IocLookupContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { api } from '../../services/api.js'
import { LOOKUP_TYPES, verdictMeta } from '../../domain/enrichment.js'
import { Badge, Button } from '../ui/index.js'

/*
 * The artifact as an indicator: the value it is the analysis of (a file's or
 * an e-mail's SHA-256, a scanned address) and its reputation among the
 * sources, one click from the indicator's page. The artifact's own verdict is
 * what Nik saw; this is what the others say.
 */

/** @param {{ indicator: { type: string, value: string } | null }} props */
export default function AsIndicator({ indicator }) {
  const { showToast } = useToast()
  const [data, setData] = useState(null)
  const [busy, setBusy] = useState(false)
  const type = indicator?.type
  const value = indicator?.value

  useEffect(() => {
    setData(null)
    if (!type || !LOOKUP_TYPES.has(type)) return undefined
    let cancelled = false
    api
      .get(`/enrichment?${new URLSearchParams({ type, value })}`)
      .then((doc) => !cancelled && setData(doc))
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [type, value])

  const check = useCallback(async () => {
    setBusy(true)
    try {
      setData(await api.post('/enrichment/check', { type, value, force: false }))
    } catch (err) {
      showToast({ message: err.message })
    } finally {
      setBusy(false)
    }
  }, [type, value, showToast])

  if (!indicator) return null
  const summary = data?.summary
  const meta = summary ? verdictMeta(summary.verdict) : null
  return (
    <span className="flex min-w-0 flex-wrap items-center gap-2">
      <span className="font-mono text-[11px] text-fg-muted">{type}</span>
      <IocValue type={type} value={value} className="break-all font-mono text-xs" />
      {meta ? (
        <Badge color={meta.color} title={`${summary.flagged} of ${summary.checked} sources flag it`}>
          Reputation: {meta.label} {summary.score}
        </Badge>
      ) : data?.blocked ? (
        <Badge title={data.blocked}>never sent out</Badge>
      ) : (
        <Badge>Reputation: not checked</Badge>
      )}
      {data && !data.blocked && data.providers.length > 0 && (
        <Button size="xs" variant="ghost" icon={Radar} disabled={busy} onClick={check}>
          {busy ? 'Checking…' : summary ? 'Check again' : 'Check reputation'}
        </Button>
      )}
    </span>
  )
}
