import { useState } from 'react'
import { Binary, Bug, Download, FileCode, Mail, Paperclip } from 'lucide-react'
import { Badge, Button } from '../../ui/index.js'
import HexView from './HexView.jsx'
import { IocValue } from '../../../context/IocLookupContext.jsx'
import { formatBytes } from '../../../utils/events.js'
import { verdictMeta } from '../../../utils/mail.js'

/*
 * The attachments, each with what it really is (from its bytes, not its
 * name) and why it may be dangerous: macros, encrypted archives (with the
 * password when the message gives it), executables in disguise, QR codes,
 * calendar links. Actions: the bytes in hex, a protected-zip download, and
 * "Send to Malware Analysis" (stored as a sample of the incident). An
 * attached message is analysed like the message itself.
 */

const SEVERITY_COLOR = { high: 'red', medium: 'amber', low: 'slate' }

function Findings({ findings }) {
  if (!findings.length) return null
  return (
    <span className="flex flex-wrap gap-1">
      {findings.map((f) => (
        <Badge key={f.id} color={SEVERITY_COLOR[f.severity]}>
          {f.label}
        </Badge>
      ))}
    </span>
  )
}

function Attachment({ item, sha256, onDownload, onSend, sending }) {
  const [hex, setHex] = useState(false)
  const [macros, setMacros] = useState(false)
  const hasBytes = item.size > 0
  const nested = item.message
  return (
    <li className="space-y-2 border border-line p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0 space-y-1">
          <p className="flex items-center gap-2 font-mono text-sm font-semibold text-fg">
            {nested ? (
              <Mail className="h-4 w-4 shrink-0 text-accent" aria-hidden="true" />
            ) : (
              <Paperclip className="h-4 w-4 shrink-0 text-fg-muted" aria-hidden="true" />
            )}
            <span className="break-all">{item.name}</span>
            {item.inline && <Badge>inline</Badge>}
          </p>
          <p className="font-mono text-[11px] text-fg-muted">
            {item.type.label} · {formatBytes(item.size)}
            {item.contentType && ` · declared ${item.contentType}`}
          </p>
        </div>
        {hasBytes && (
          <span className="flex flex-wrap gap-1">
            <Button variant="ghost" size="xs" icon={Binary} onClick={() => setHex((v) => !v)} aria-expanded={hex}>
              Hex
            </Button>
            <Button variant="ghost" size="xs" icon={Download} onClick={() => onDownload(item)}>
              Zip
            </Button>
            <Button
              variant="secondary"
              size="xs"
              icon={Bug}
              onClick={() => onSend(item)}
              disabled={sending === item.path}
            >
              {sending === item.path ? 'Sending…' : 'Send to Malware Analysis'}
            </Button>
          </span>
        )}
      </div>

      <Findings findings={item.findings} />

      {item.hashes && (
        <p className="font-mono text-[11px] text-fg-muted">
          sha256 <IocValue type="sha256" value={item.hashes.sha256} className="text-fg" />
        </p>
      )}

      {item.archive && (
        <div className="font-mono text-[11px]">
          <p className="text-fg-muted">
            {item.archive.total} file{item.archive.total === 1 ? '' : 's'}
            {item.archive.encrypted &&
              (item.archive.password ? ` · password “${item.archive.password}” works` : ' · password not found')}
          </p>
          <ul className="mt-1 space-y-0.5">
            {item.archive.entries.map((entry) => (
              <li key={entry.name} className={entry.risky ? 'text-high' : 'text-fg'}>
                {entry.name}{' '}
                <span className="text-fg-subtle">
                  {formatBytes(entry.size)}
                  {entry.type ? ` · ${entry.type.label}` : ''}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {item.macros && (
        <div className="space-y-1 font-mono text-[11px]">
          <p className="text-fg-muted">
            VBA modules: {item.macros.modules.join(', ') || '—'}
            {item.macros.suspicious.length > 0 && ` · suspicious: ${item.macros.suspicious.join(', ')}`}
          </p>
          {item.macros.source && (
            <>
              <Button
                variant="ghost"
                size="xs"
                icon={FileCode}
                onClick={() => setMacros((v) => !v)}
                aria-expanded={macros}
              >
                {macros ? 'Hide macro source' : 'Show macro source'}
              </Button>
              {macros && (
                <pre className="max-h-80 overflow-auto border border-line bg-canvas p-2 text-fg">
                  {item.macros.source}
                  {item.macros.truncated && '\n… (truncated)'}
                </pre>
              )}
            </>
          )}
        </div>
      )}

      {item.qrCodes?.length > 0 && (
        <p className="font-mono text-[11px] text-fg-muted">
          QR code →{' '}
          {item.qrCodes.map((code) =>
            /^https?:\/\//i.test(code) ? (
              <IocValue key={code} type="url" value={code} />
            ) : (
              <span key={code}>{code}</span>
            ),
          )}
        </p>
      )}

      {item.calendar && (
        <dl className="grid grid-cols-[6rem_minmax(0,1fr)] gap-x-3 font-mono text-[11px]">
          {['summary', 'organizer', 'dtstart', 'location'].map(
            (key) =>
              item.calendar[key] && (
                <div key={key} className="contents">
                  <dt className="text-fg-muted">{key}</dt>
                  <dd className="break-all text-fg">{item.calendar[key]}</dd>
                </div>
              ),
          )}
          {item.calendar.urls.map((url) => (
            <div key={url} className="contents">
              <dt className="text-fg-muted">link</dt>
              <dd>
                <IocValue type="url" value={url} />
              </dd>
            </div>
          ))}
        </dl>
      )}

      {item.pdf && <p className="font-mono text-[11px] text-fg-muted">PDF actions: {item.pdf.actions.join(', ')}</p>}

      {hex && <HexView sha256={sha256} path={item.path} />}

      {nested && (
        <div className="space-y-2 border-l-2 border-line pl-3">
          <p className="flex flex-wrap items-center gap-2 font-mono text-xs">
            <Badge color={verdictMeta(nested.verdict).color}>
              {verdictMeta(nested.verdict).label} · {nested.score}
            </Badge>
            <span className="text-fg">{nested.subject || '(no subject)'}</span>
            <span className="text-fg-muted">{nested.sender.from.address}</span>
          </p>
          {nested.findings.length > 0 && (
            <ul className="space-y-0.5 font-mono text-[11px] text-fg-muted">
              {nested.findings.slice(0, 6).map((f) => (
                <li key={f.id}>· {f.label}</li>
              ))}
            </ul>
          )}
          {nested.attachments.length > 0 && (
            <MailAttachments
              attachments={nested.attachments}
              sha256={sha256}
              onDownload={onDownload}
              onSend={onSend}
              sending={sending}
            />
          )}
        </div>
      )}
    </li>
  )
}

export default function MailAttachments({ attachments, sha256, onDownload, onSend, sending }) {
  if (!attachments.length) return <p className="font-mono text-xs text-fg-muted">No attachment.</p>
  return (
    <ul className="space-y-2">
      {attachments.map((item) => (
        <Attachment
          key={item.path}
          item={item}
          sha256={sha256}
          onDownload={onDownload}
          onSend={onSend}
          sending={sending}
        />
      ))}
    </ul>
  )
}
