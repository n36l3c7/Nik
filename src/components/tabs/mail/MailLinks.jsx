import { Globe } from 'lucide-react'
import { Badge } from '../../ui/index.js'
import { IocValue } from '../../../context/IocLookupContext.jsx'

/*
 * Every link of the message: where it really goes (security gateways such as
 * Safe Links or Proofpoint unwrapped), the text the reader saw, and why it is
 * suspicious. Flagged links first. Nothing here opens the link.
 */

const SEVERITY_COLOR = { high: 'red', medium: 'amber', low: 'slate' }

export default function MailLinks({ links, onOpenUrl = null }) {
  if (!links.length) return <p className="font-mono text-xs text-fg-muted">The message holds no link.</p>
  const ordered = [...links].sort((a, b) => b.findings.length - a.findings.length)
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] table-fixed border-collapse font-mono text-xs">
        <thead>
          <tr className="border-b border-line text-left text-fg-muted">
            <th className="w-[44%] py-1.5 font-normal">target</th>
            <th className="w-[24%] py-1.5 font-normal">shown as</th>
            <th className="py-1.5 font-normal">findings</th>
          </tr>
        </thead>
        <tbody>
          {ordered.map((link, i) => {
            const isWeb = /^https?:\/\//i.test(link.target)
            return (
              <tr key={i} className="border-b border-line-soft align-top">
                <td className="py-2 pr-3">
                  {isWeb ? (
                    <IocValue type="url" value={link.target} />
                  ) : (
                    <span className="break-all">{link.target}</span>
                  )}
                  {link.gateway && (
                    <span className="mt-0.5 block text-[11px] text-fg-subtle" title={link.url}>
                      unwrapped from {link.gateway}
                    </span>
                  )}
                  {link.displayHost && link.displayHost !== link.host && (
                    <span className="mt-0.5 block text-[11px] text-high">reads as {link.displayHost}</span>
                  )}
                  {isWeb && onOpenUrl && (
                    <button
                      type="button"
                      onClick={() => onOpenUrl(link.target)}
                      className="mt-1 inline-flex items-center gap-1 text-[11px] text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    >
                      <Globe className="h-3 w-3" aria-hidden="true" /> open in isolated browser
                    </button>
                  )}
                </td>
                <td className="break-words py-2 pr-3 text-fg-muted">
                  {link.kind === 'form' ? (
                    <Badge color="red">form</Badge>
                  ) : (
                    link.text || <span className="text-fg-subtle">—</span>
                  )}
                </td>
                <td className="py-2">
                  <span className="flex flex-wrap gap-1">
                    {link.findings.map((f) => (
                      <Badge key={f.id} color={SEVERITY_COLOR[f.severity]}>
                        {f.label}
                      </Badge>
                    ))}
                    {link.allowlisted && <Badge color="emerald">allowlisted</Badge>}
                    {!link.findings.length && !link.allowlisted && <span className="text-fg-subtle">—</span>}
                  </span>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
