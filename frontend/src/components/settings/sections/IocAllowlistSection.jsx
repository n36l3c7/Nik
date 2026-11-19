import { RotateCcw, ShieldCheck } from 'lucide-react'
import { Button } from '../../ui/index.js'
import { useSettings } from '../../../context/SettingsContext.jsx'
import ListPicker from '../ListPicker.jsx'

/*
 * IOC allowlist: well-known values hidden by default in the IOCs tab and left
 * out of the CSV / STIX / MISP exports. Shared by every analyst. The index
 * keeps everything, so a change applies at once to every incident.
 *
 * The allowlist is a list (Settings → Lists): this section says which list
 * is read, and puts the factory entries back. An indicator is still added to
 * it from its right-click menu.
 */

export default function IocAllowlistSection() {
  const { iocAllowlist, iocAllowlistDefault, setIocAllowlist } = useSettings()
  const loaded = Array.isArray(iocAllowlist)
  const entries = (iocAllowlist ?? []).filter((entry) => entry.trim() && !entry.trim().startsWith('#'))

  return (
    <section className="space-y-4">
      <div>
        <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
          <ShieldCheck className="h-4 w-4 text-accent" />
          IOC allowlist
        </h3>
        <p className="mt-1 text-xs text-fg-muted">
          An entry is a domain (also matches its subdomains, and URLs and e-mail addresses on it), an IP address or CIDR
          network (<code>10.0.0.0/8</code>), or an exact value such as a hash. An item starting with <code>#</code> is a
          comment. Matching indicators are hidden by default in the Indicators tab and never exported.
        </p>
      </div>
      <ListPicker
        setting="iocAllowlist"
        label="Allowlist"
        hint="Its entries are edited in Lists; right-click an indicator to add it from where you see it."
      />
      <div className="flex flex-wrap items-center gap-2">
        <Button
          variant="secondary"
          icon={RotateCcw}
          size="sm"
          onClick={() => setIocAllowlist(iocAllowlistDefault)}
          disabled={!loaded || iocAllowlistDefault.length === 0}
        >
          Restore defaults
        </Button>
        <span className="text-xs text-fg-muted">{loaded ? `${entries.length} entries` : 'Loading…'}</span>
      </div>
    </section>
  )
}
