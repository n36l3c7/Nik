import { useEffect, useState } from 'react'
import { RotateCcw, Save, ShieldCheck } from 'lucide-react'
import { Button } from '../../ui/index.js'
import { useSettings } from '../../../context/SettingsContext.jsx'

/*
 * IOC allowlist: well-known values hidden by default in the IOCs tab and left
 * out of the CSV / STIX / MISP exports. Shared by every analyst. The index
 * keeps everything, so a change applies at once to every incident.
 */

const toText = (list) => (list ?? []).join('\n')

export default function IocAllowlistSection() {
  const { iocAllowlist, iocAllowlistDefault, setIocAllowlist } = useSettings()
  const [draft, setDraft] = useState(() => toText(iocAllowlist))
  const loaded = Array.isArray(iocAllowlist)

  useEffect(() => {
    setDraft(toText(iocAllowlist))
  }, [iocAllowlist])

  const entries = draft.split('\n')
  const dirty =
    toText(iocAllowlist) !==
    entries
      .map((e) => e.trim())
      .filter(Boolean)
      .join('\n')

  return (
    <section className="space-y-4">
      <div>
        <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
          <ShieldCheck className="h-4 w-4 text-accent" />
          IOC allowlist
        </h3>
        <p className="mt-1 text-xs text-fg-muted">
          One entry per line: a domain (also matches its subdomains, and URLs and e-mail addresses on it), an IP address
          or CIDR network (<code>10.0.0.0/8</code>), or an exact value such as a hash. Lines starting with{' '}
          <code>#</code> are comments. Matching indicators are hidden by default in the IOCs tab and never exported.
        </p>
      </div>
      <textarea
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        disabled={!loaded}
        rows={16}
        spellCheck={false}
        aria-label="IOC allowlist entries"
        className="w-full border border-line bg-canvas p-3 font-mono text-xs text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        placeholder={loaded ? 'example.com' : 'Loading…'}
      />
      <div className="flex flex-wrap items-center gap-2">
        <Button icon={Save} size="sm" onClick={() => setIocAllowlist(entries)} disabled={!loaded || !dirty}>
          Save
        </Button>
        <Button
          variant="secondary"
          icon={RotateCcw}
          size="sm"
          onClick={() => setIocAllowlist(iocAllowlistDefault)}
          disabled={!loaded || iocAllowlistDefault.length === 0}
        >
          Restore defaults
        </Button>
        <span className="text-xs text-fg-muted">
          {entries.filter((e) => e.trim() && !e.trim().startsWith('#')).length} entries
        </span>
      </div>
    </section>
  )
}
