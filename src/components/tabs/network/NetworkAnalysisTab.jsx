import { useCallback, useEffect, useRef, useState } from 'react'
import { Network, PanelLeftClose, PanelLeftOpen } from 'lucide-react'
import { AsciiSkull, Badge, Button, Card, EmptyState } from '../../ui/index.js'
import SampleDropZone from '../malware/SampleDropZone.jsx'
import DownloadDialog from '../malware/DownloadDialog.jsx'
import CaptureDetail from './CaptureDetail.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { useNavigation } from '../../../context/NavigationContext.jsx'
import { useToast } from '../../../context/ToastContext.jsx'
import { api, upload } from '../../../services/api.js'
import { formatBytes } from '../../../utils/events.js'

/*
 * ============================================================================
 * NETWORK ANALYSIS TAB — packet captures, with Wireshark's engine
 * ============================================================================
 * The analyst drops a pcap / pcapng (a TLS key log can be added to decrypt
 * HTTPS); the server stores it and the packet capture worker analyses it
 * with tshark and sharkd. The isolated browser's sessions opened from this
 * incident appear here too, rebuilt as pcapng when they end. The incident
 * keeps light references (data.network.captures); the views ask the server.
 */

const MAX_MB = 500
const NO_CAPTURES = []
const POLL_MS = 3000
/** The light reference of a capture (what the incident keeps) from its full detail. */
const captureRef = (doc) =>
  Object.fromEntries(Object.entries(doc).filter(([k]) => !['meta', 'summary', 'incidentId'].includes(k)))

const STATUS_COLOR = { live: 'cyan', indexing: 'amber', ready: 'emerald', error: 'red', stored: 'slate' }

function CaptureList({ captures, selected, onSelect }) {
  return (
    <ul aria-label="Captures" className="divide-y divide-line-soft font-mono text-xs">
      {captures.map((c) => (
        <li key={c.id}>
          <button
            type="button"
            onClick={() => onSelect(c.id)}
            aria-current={c.id === selected ? 'true' : undefined}
            className={[
              'grid w-full grid-cols-[minmax(0,1fr)_auto] gap-x-2 gap-y-1 border-l-2 px-3 py-2.5 text-left transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent',
              c.id === selected ? 'border-l-accent bg-raised' : 'border-l-transparent hover:bg-raised',
            ].join(' ')}
          >
            <span className="truncate font-semibold text-fg" title={c.fileName}>
              {c.kind === 'browser' ? c.label || c.fileName : c.fileName}
            </span>
            <Badge color={STATUS_COLOR[c.status] ?? 'slate'}>{c.status === 'ready' ? c.packets : c.status}</Badge>
            <span className="col-span-2 truncate text-[11px] text-fg-subtle">
              {c.kind === 'browser' ? 'isolated browser' : 'pcap'} · {formatBytes(c.size)}
              {c.held?.length ? ` · ${c.held.length} held` : ''}
              {c.beacons?.length ? ` · ${c.beacons.length} beacon${c.beacons.length > 1 ? 's' : ''}` : ''}
            </span>
          </button>
        </li>
      ))}
    </ul>
  )
}

export default function NetworkAnalysisTab({ incident }) {
  const { putCapture, syncCaptures, removeCapture, attachSample, toggleFlag } = useIncidents()
  const { showToast } = useToast()
  const { requests, take, goTo } = useNavigation()
  const captures = incident.data.network?.captures ?? NO_CAPTURES

  const [selected, setSelected] = useState(captures[0]?.id ?? null)
  const [details, setDetails] = useState({})
  const [errors, setErrors] = useState({})
  const [progress, setProgress] = useState(null)
  const [uploadError, setUploadError] = useState(null)
  const [listOpen, setListOpen] = useState(true)
  const [removing, setRemoving] = useState(false)
  const [downloading, setDownloading] = useState(null)
  const [sending, setSending] = useState(null)
  const keylogInput = useRef(null)

  useEffect(() => {
    if (!captures.some((c) => c.id === selected)) setSelected(captures[0]?.id ?? null)
  }, [captures, selected])

  const fetchDetail = useCallback(
    (id) =>
      api
        .get(`/captures/${id}`)
        .then((doc) => {
          setDetails((prev) => ({ ...prev, [id]: doc }))
          putCapture(incident.id, captureRef(doc))
        })
        .catch((err) => setErrors((prev) => ({ ...prev, [id]: err.message }))),
    [incident.id, putCapture],
  )

  // The server's list: isolated browser sessions are added there, by any analyst.
  useEffect(() => {
    let cancelled = false
    api
      .get(`/incidents/${encodeURIComponent(incident.id)}/captures`)
      .then((res) => !cancelled && syncCaptures(incident.id, res.captures))
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [incident.id, syncCaptures])

  const current = captures.find((c) => c.id === selected) ?? null
  const busy = current && ['indexing', 'live'].includes(current.status)
  useEffect(() => {
    if (!current) return undefined
    if (!details[current.id] || details[current.id].status !== current.status) fetchDetail(current.id)
    if (!busy) return undefined
    const timer = setInterval(() => fetchDetail(current.id), POLL_MS)
    return () => clearInterval(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [current?.id, current?.status, busy, fetchDetail])

  const handleFiles = async (files) => {
    setUploadError(null)
    for (const file of files) {
      if (file.size > MAX_MB * 1024 * 1024) {
        setUploadError(`${file.name} exceeds the ${MAX_MB} MB limit.`)
        continue
      }
      setProgress({ fileName: file.name, sent: 0, total: file.size })
      try {
        const result = await upload(`/incidents/${encodeURIComponent(incident.id)}/captures`, file, {
          onProgress: ({ sent, total }) => setProgress({ fileName: file.name, sent, total }),
        })
        putCapture(incident.id, result.capture)
        setSelected(result.capture.id)
      } catch (err) {
        setUploadError(`${file.name}: ${err.message}`)
      }
    }
    setProgress(null)
  }

  // A file dropped anywhere in the app for this tab (see NavigationContext).
  useEffect(() => {
    if (!requests.network) return
    const request = take('network')
    if (request?.file) handleFiles([request.file])
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requests.network])

  const act = async (work, message) => {
    try {
      const ref = await work()
      if (ref?.id) putCapture(incident.id, ref)
      if (current) fetchDetail(current.id)
    } catch (err) {
      showToast({ message: `${message}: ${err.message}` })
    }
  }

  const handleKeylog = (file) => {
    if (file && current) act(() => upload(`/captures/${current.id}/keylog`, file, { method: 'PUT' }), 'TLS keys')
  }

  const handleSend = async (object) => {
    setSending(object.token)
    try {
      const result = await api.post(
        `/incidents/${encodeURIComponent(incident.id)}/captures/${current.id}/objects/sample`,
        { token: object.token },
      )
      attachSample(incident.id, result.sample)
      showToast({
        message: `${object.name || 'The object'} is now a sample of this incident.`,
        action: { label: 'Open', run: () => goTo('malware') },
      })
    } catch (err) {
      showToast({ message: `${object.name}: ${err.message}` })
    } finally {
      setSending(null)
    }
  }

  const dropZone = (compact) => (
    <SampleDropZone
      compact={compact}
      onFiles={handleFiles}
      progress={progress}
      maxMb={MAX_MB}
      title="Drop captures here"
      label="Upload packet captures"
      accept=".pcap,.pcapng,.cap,.gz"
      hint={compact ? 'pcap or pcapng' : `pcap or pcapng (gzip too) · up to ${MAX_MB} MB · read by Wireshark's engine`}
    />
  )

  if (captures.length === 0) {
    return (
      <EmptyState
        illustration={<AsciiSkull preset="medium" eyes="closed" tone="muted" />}
        title="No captures yet"
        message="Drop a pcap or pcapng to read it as in Wireshark: packet list, protocol tree, bytes, display filters, Follow Stream, Export Objects. Sessions of the isolated browser opened from this incident appear here too."
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
      className={`grid gap-4 ${listOpen ? 'lg:grid-cols-[260px_minmax(0,1fr)]' : 'lg:grid-cols-[auto_minmax(0,1fr)]'}`}
    >
      {listOpen ? (
        <Card
          title={`Captures · ${captures.length}`}
          icon={Network}
          actions={
            <Button
              variant="ghost"
              size="xs"
              icon={PanelLeftClose}
              aria-label="Hide the capture list"
              onClick={() => setListOpen(false)}
            />
          }
          bodyClassName="p-0"
        >
          <CaptureList captures={captures} selected={selected} onSelect={setSelected} />
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
            aria-label="Show the capture list"
            onClick={() => setListOpen(true)}
          />
        </div>
      )}

      {current && (
        <CaptureDetail
          key={current.id}
          incident={incident}
          capture={current}
          detail={details[current.id] ?? null}
          error={errors[current.id] ?? null}
          removing={removing}
          onRemove={async () => {
            setRemoving(true)
            try {
              await removeCapture(incident.id, current.id)
            } catch (err) {
              showToast({ message: `${current.fileName}: ${err.message}` })
            } finally {
              setRemoving(false)
            }
          }}
          onReanalyse={() => act(() => api.post(`/captures/${current.id}/reanalyse`), 'Re-analyse')}
          onKeylog={() => keylogInput.current?.click()}
          onRemoveKeylog={() => act(() => api.del(`/captures/${current.id}/keylog`), 'TLS keys')}
          onDownloadObject={(object) =>
            setDownloading({
              fileName: object.name || 'object',
              sha256: current.id,
              downloadPath: `/captures/${current.id}/objects/download?token=${encodeURIComponent(object.token)}`,
            })
          }
          onSendObject={handleSend}
          sending={sending}
          onFlag={(packet, time) =>
            toggleFlag(incident.id, {
              key: `pcap:${current.id}:${packet.num}`,
              browserId: 'network',
              section: 'network',
              eventType: 'network',
              title: `${packet.c[4]} ${packet.c[6]}`.slice(0, 300),
              url: `${packet.c[2]} → ${packet.c[3]} · ${current.fileName} #${packet.num}`,
              time,
            })
          }
        />
      )}
      <input
        ref={keylogInput}
        type="file"
        hidden
        accept=".log,.txt,.keys"
        aria-label="TLS key log"
        onChange={(event) => {
          handleKeylog(event.target.files?.[0])
          event.target.value = ''
        }}
      />
      <DownloadDialog sample={downloading} onClose={() => setDownloading(null)} />
    </div>
  )
}
