import { useCallback, useEffect, useRef, useState } from 'react'
import { Mail, PanelLeftClose, PanelLeftOpen } from 'lucide-react'
import { AsciiSkull, Badge, Button, Card, EmptyState } from '../../ui/index.js'
import SampleDropZone from '../malware/SampleDropZone.jsx'
import DownloadDialog from '../malware/DownloadDialog.jsx'
import MailDetail from './MailDetail.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { useNavigation } from '../../../context/NavigationContext.jsx'
import { useToast } from '../../../context/ToastContext.jsx'
import { api, upload } from '../../../services/api.js'
import { formatDateTime } from '../../../utils/time.js'
import { verdictMeta } from '../../../utils/mail.js'

/*
 * ============================================================================
 * MAIL ANALYSIS TAB — phishing triage of .eml and Outlook .msg files
 * ============================================================================
 * The analyst drops a message; the Nik server stores it, reads the headers
 * and the route, checks SPF/DKIM/DMARC through DNS, cleans the HTML body,
 * looks at every link and attachment and weighs the evidence into a verdict.
 * The incident keeps light references (data.mail.messages); the analysis is
 * fetched per message from GET /api/mails/{sha256}.
 */

const MAIL_MAX_MB = 100
const NO_MESSAGES = []

function MessageList({ messages, selected, onSelect }) {
  return (
    <ul aria-label="Messages" className="divide-y divide-line-soft font-mono text-xs">
      {messages.map((m) => {
        const active = m.sha256 === selected
        const verdict = verdictMeta(m.verdict)
        return (
          <li key={m.sha256}>
            <button
              type="button"
              onClick={() => onSelect(m.sha256)}
              aria-current={active ? 'true' : undefined}
              className={[
                'grid w-full grid-cols-[minmax(0,1fr)_auto] gap-x-2 gap-y-1 border-l-2 px-3 py-2.5 text-left transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent',
                active ? 'border-l-accent bg-raised' : 'border-l-transparent hover:bg-raised',
              ].join(' ')}
            >
              <span className="truncate font-semibold text-fg" title={m.subject}>
                {m.subject || m.fileName}
              </span>
              <Badge color={verdict.color}>{m.score}</Badge>
              <span className="col-span-2 truncate text-[11px] text-fg-subtle">
                {m.from || '?'} · {m.date ? formatDateTime(m.date) : m.fileName}
              </span>
            </button>
          </li>
        )
      })}
    </ul>
  )
}

export default function MailAnalysisTab({ incident }) {
  const { attachMail, detachMail, attachSample } = useIncidents()
  const { showToast } = useToast()
  const { requests, take, goTo } = useNavigation()
  const messages = incident.data.mail?.messages ?? NO_MESSAGES

  const [selected, setSelected] = useState(messages[0]?.sha256 ?? null)
  const [details, setDetails] = useState({})
  const [detailErrors, setDetailErrors] = useState({})
  const [progress, setProgress] = useState(null)
  const [uploadError, setUploadError] = useState(null)
  const [listOpen, setListOpen] = useState(true)
  const [removing, setRemoving] = useState(false)
  const [reanalysing, setReanalysing] = useState(false)
  const [downloading, setDownloading] = useState(null)
  const [sending, setSending] = useState(null)
  const pending = useRef(new Set())

  useEffect(() => {
    if (!messages.some((m) => m.sha256 === selected)) setSelected(messages[0]?.sha256 ?? null)
  }, [messages, selected])

  const fetchDetail = useCallback((sha256) => {
    if (pending.current.has(sha256)) return
    pending.current.add(sha256)
    api
      .get(`/mails/${sha256}`)
      .then((doc) => setDetails((prev) => ({ ...prev, [sha256]: doc })))
      .catch((err) => setDetailErrors((prev) => ({ ...prev, [sha256]: err.message })))
      .finally(() => pending.current.delete(sha256))
  }, [])

  useEffect(() => {
    if (selected && !details[selected] && !detailErrors[selected]) fetchDetail(selected)
  }, [selected, details, detailErrors, fetchDetail])

  const handleFiles = async (files) => {
    setUploadError(null)
    for (const file of files) {
      if (file.size > MAIL_MAX_MB * 1024 * 1024) {
        setUploadError(`${file.name} exceeds the ${MAIL_MAX_MB} MB limit.`)
        continue
      }
      setProgress({ fileName: file.name, sent: 0, total: file.size })
      try {
        const result = await upload(`/incidents/${encodeURIComponent(incident.id)}/mails`, file, {
          onProgress: ({ sent, total }) => setProgress({ fileName: file.name, sent, total }),
        })
        attachMail(incident.id, result.message)
        setSelected(result.message.sha256)
      } catch (err) {
        setUploadError(`${file.name}: ${err.message}`)
      }
    }
    setProgress(null)
  }

  // A file dropped anywhere in the app for this tab (see NavigationContext).
  useEffect(() => {
    if (!requests.mail) return
    const request = take('mail')
    if (request?.file) handleFiles([request.file])
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requests.mail])

  const handleRemove = async (message) => {
    setRemoving(true)
    try {
      await detachMail(incident.id, message.sha256)
    } catch (err) {
      setUploadError(`${message.fileName}: ${err.message}`)
    } finally {
      setRemoving(false)
    }
  }

  const handleReanalyse = async (message) => {
    setReanalysing(true)
    try {
      const doc = await api.post(`/mails/${message.sha256}/reanalyse`)
      setDetails((prev) => ({ ...prev, [message.sha256]: doc }))
    } catch (err) {
      setUploadError(`${message.fileName}: ${err.message}`)
    } finally {
      setReanalysing(false)
    }
  }

  const handleSend = async (message, item) => {
    setSending(item.path)
    try {
      const result = await api.post(
        `/incidents/${encodeURIComponent(incident.id)}/mails/${message.sha256}/attachments/${item.path}/sample`,
      )
      attachSample(incident.id, result.sample)
      showToast({
        message: `${item.name} is now a sample of this incident.`,
        action: { label: 'Open', run: () => goTo('malware') },
      })
    } catch (err) {
      showToast({ message: `${item.name}: ${err.message}` })
    } finally {
      setSending(null)
    }
  }

  const current = messages.find((m) => m.sha256 === selected) ?? null
  const dropZone = (compact) => (
    <SampleDropZone
      compact={compact}
      onFiles={handleFiles}
      progress={progress}
      maxMb={MAIL_MAX_MB}
      title="Drop e-mails here"
      label="Upload e-mails"
      accept=".eml,.msg,message/rfc822,application/vnd.ms-outlook"
      hint={compact ? '.eml or .msg' : `.eml or Outlook .msg · up to ${MAIL_MAX_MB} MB · nothing is opened or run`}
    />
  )

  if (messages.length === 0) {
    return (
      <EmptyState
        illustration={<AsciiSkull preset="medium" eyes="closed" tone="muted" />}
        title="No e-mails yet"
        message="Drop a reported message (.eml, or .msg saved from Outlook) to read its route and authentication, check its links and attachments, and get a phishing verdict with the evidence behind it."
        action={
          <div className="w-full max-w-md">
            {dropZone(false)}
            {uploadError && (
              <p role="alert" className="mt-2 font-mono text-xs text-high">
                {uploadError}
              </p>
            )}
          </div>
        }
      />
    )
  }

  return (
    <div
      className={`grid gap-4 ${listOpen ? 'lg:grid-cols-[280px_minmax(0,1fr)]' : 'lg:grid-cols-[auto_minmax(0,1fr)]'}`}
    >
      {listOpen ? (
        <Card
          title={`E-mails · ${messages.length}`}
          icon={Mail}
          actions={
            <Button
              variant="ghost"
              size="xs"
              icon={PanelLeftClose}
              aria-label="Hide the message list"
              onClick={() => setListOpen(false)}
            />
          }
          bodyClassName="p-0"
        >
          <MessageList messages={messages} selected={selected} onSelect={setSelected} />
          <div className="border-t border-line p-3">
            {dropZone(true)}
            {uploadError && (
              <p role="alert" className="mt-2 font-mono text-xs text-high">
                {uploadError}
              </p>
            )}
          </div>
        </Card>
      ) : (
        <div>
          <Button
            variant="ghost"
            size="xs"
            icon={PanelLeftOpen}
            aria-label="Show the message list"
            onClick={() => setListOpen(true)}
          />
        </div>
      )}

      {current && (
        <MailDetail
          incident={incident}
          message={current}
          detail={details[current.sha256] ?? null}
          error={detailErrors[current.sha256] ?? null}
          onRemove={() => handleRemove(current)}
          removing={removing}
          onReanalyse={() => handleReanalyse(current)}
          reanalysing={reanalysing}
          onDownload={(item) =>
            setDownloading({
              fileName: item.name,
              sha256: current.sha256,
              downloadPath: `/mails/${current.sha256}/attachments/${item.path}/download`,
            })
          }
          onSend={(item) => handleSend(current, item)}
          sending={sending}
        />
      )}

      <DownloadDialog sample={downloading} onClose={() => setDownloading(null)} />
    </div>
  )
}
