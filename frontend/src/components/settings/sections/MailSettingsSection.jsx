import { Mail } from 'lucide-react'
import { useSettings } from '../../../context/SettingsContext.jsx'
import ListPicker from '../ListPicker.jsx'

/*
 * Mail Analysis settings, shared by every analyst:
 *   - your organisation's domains: a message that claims to come from them
 *     but fails authentication, or a domain that imitates them, is flagged;
 *   - your mail servers and gateways (Exchange Online, Google, Proofpoint,
 *     Mimecast…): only their Authentication-Results headers are believed,
 *     since anyone can write such a header into a message. Their hops are
 *     also skipped when looking for the sending server.
 * Both are lists (Settings → Lists): this section says which list each reads.
 * Re-analyse a message to apply a change to it.
 */

function Held({ title, values }) {
  return (
    <p className="text-xs text-fg-muted">
      {title}: {values?.length ? <span className="font-mono text-fg">{values.join(', ')}</span> : <em>none yet</em>}
    </p>
  )
}

export default function MailSettingsSection() {
  const { mailSettings } = useSettings()
  return (
    <section className="space-y-4">
      <div>
        <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
          <Mail className="h-4 w-4 text-accent" />
          Mail analysis
        </h3>
        <p className="mt-1 text-xs text-fg-muted">
          A domain also covers its subdomains. Changes apply to messages analysed from now on; re-analyse a message to
          apply them to it.
        </p>
      </div>
      <div className="space-y-1.5">
        <ListPicker
          setting="mail.orgDomains"
          label="Your organisation's domains"
          hint="Messages claiming to come from them must pass authentication; look-alike domains are flagged."
        />
        <Held title="It holds" values={mailSettings?.orgDomains} />
      </div>
      <div className="space-y-1.5">
        <ListPicker
          setting="mail.trustedAuthServers"
          label="Your mail servers and gateways"
          hint="Only Authentication-Results headers written by these hosts are trusted (e.g. protection.outlook.com, mx.google.com, pphosted.com, mimecast.com)."
        />
        <Held title="It holds" values={mailSettings?.trustedAuthServers} />
      </div>
    </section>
  )
}
