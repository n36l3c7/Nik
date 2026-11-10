import { useEffect, useState } from 'react'
import { Mail, Save } from 'lucide-react'
import { Button } from '../../ui/index.js'
import { useSettings } from '../../../context/SettingsContext.jsx'

/*
 * Mail Analysis settings, shared by every analyst:
 *   - your organisation's domains: a message that claims to come from them
 *     but fails authentication, or a domain that imitates them, is flagged;
 *   - your mail servers and gateways (Exchange Online, Google, Proofpoint,
 *     Mimecast…): only their Authentication-Results headers are believed,
 *     since anyone can write such a header into a message. Their hops are
 *     also skipped when looking for the sending server.
 * Re-analyse a message to apply a change to it.
 */

const toText = (list) => (list ?? []).join('\n')
const toList = (text) =>
  text
    .split(/[\s,]+/)
    .map((d) => d.trim())
    .filter(Boolean)

function DomainList({ id, label, hint, value, onChange, disabled, placeholder }) {
  return (
    <label htmlFor={id} className="block space-y-1.5">
      <span className="block text-sm font-semibold text-fg">{label}</span>
      <span className="block text-xs text-fg-muted">{hint}</span>
      <textarea
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        rows={6}
        spellCheck={false}
        placeholder={disabled ? 'Loading…' : placeholder}
        className="w-full border border-line bg-canvas p-3 font-mono text-xs text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      />
    </label>
  )
}

export default function MailSettingsSection() {
  const { mailSettings, setMailSettings } = useSettings()
  const loaded = mailSettings !== null
  const [domains, setDomains] = useState(() => toText(mailSettings?.orgDomains))
  const [servers, setServers] = useState(() => toText(mailSettings?.trustedAuthServers))

  useEffect(() => {
    setDomains(toText(mailSettings?.orgDomains))
    setServers(toText(mailSettings?.trustedAuthServers))
  }, [mailSettings])

  const dirty =
    toList(domains).join('\n') !== toText(mailSettings?.orgDomains) ||
    toList(servers).join('\n') !== toText(mailSettings?.trustedAuthServers)

  return (
    <section className="space-y-4">
      <div>
        <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
          <Mail className="h-4 w-4 text-accent" />
          Mail analysis
        </h3>
        <p className="mt-1 text-xs text-fg-muted">
          One domain per line. A domain also covers its subdomains. Changes apply to messages analysed from now on;
          re-analyse a message to apply them to it.
        </p>
      </div>
      <DomainList
        id="mail-org-domains"
        label="Your organisation's domains"
        hint="Messages claiming to come from them must pass authentication; look-alike domains are flagged."
        value={domains}
        onChange={setDomains}
        disabled={!loaded}
        placeholder="contoso.com"
      />
      <DomainList
        id="mail-trusted-servers"
        label="Your mail servers and gateways"
        hint="Only Authentication-Results headers written by these hosts are trusted (e.g. protection.outlook.com, mx.google.com, pphosted.com, mimecast.com)."
        value={servers}
        onChange={setServers}
        disabled={!loaded}
        placeholder="protection.outlook.com"
      />
      <Button
        icon={Save}
        size="sm"
        disabled={!loaded || !dirty}
        onClick={() => setMailSettings({ orgDomains: toList(domains), trustedAuthServers: toList(servers) })}
      >
        Save
      </Button>
    </section>
  )
}
