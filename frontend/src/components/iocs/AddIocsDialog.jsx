import { useEffect, useRef, useState } from 'react'
import { FileUp } from 'lucide-react'
import { api } from '../../services/api.js'
import { INDICATOR_FILE_MAX_BYTES, TLP_OPTIONS } from '../../domain/iocLibrary.js'
import { Badge, Button, Modal, Select } from '../ui/index.js'

/*
 * Add indicators: one or many, typed, pasted, or read from a file (text, CSV,
 * STIX 2.1, MISP, Nik's JSON). The server reads the text as it is typed and
 * says what it found before anything is saved. Each indicator is saved on its
 * own; whether they also go in a list is asked, never assumed.
 */

const INPUT =
  'border border-line bg-canvas px-2.5 py-1.5 font-mono text-xs text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const FORMATS = { text: 'text', csv: 'CSV', stix: 'STIX 2.1', misp: 'MISP event', nik: 'Nik export' }

function Row({ label, hint, value }) {
  return (
    <li className="flex items-baseline justify-between gap-3 border-b border-line-soft py-1.5 text-sm">
      <span>
        {label} {hint && <span className="text-xs text-fg-subtle">{hint}</span>}
      </span>
      <b className="font-mono tabular-nums">{value}</b>
    </li>
  )
}

/**
 * @param {{
 *   request: { text?: string, fileName?: string, origin?: 'manual' | 'import', list?: string,
 *              onNotIndicators?: () => void } | null,
 *   lists: object[],
 *   onClose: () => void,
 *   onSaved: (result: object) => void,
 * }} props
 */
export default function AddIocsDialog({ request, lists, onClose, onSaved }) {
  const [text, setText] = useState('')
  const [fileName, setFileName] = useState('')
  const [parsed, setParsed] = useState(null)
  const [reading, setReading] = useState(false)
  const [group, setGroup] = useState('none') // none | new | <list id>
  const [listName, setListName] = useState('')
  const [watch, setWatch] = useState(false)
  const [tags, setTags] = useState('')
  const [note, setNote] = useState('')
  const [tlp, setTlp] = useState('amber')
  const [expires, setExpires] = useState('')
  const [check, setCheck] = useState(true)
  const [showUnknown, setShowUnknown] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const fileInput = useRef(null)
  const requestRef = useRef(0)

  useEffect(() => {
    if (!request) return
    setText(request.text ?? '')
    setFileName(request.fileName ?? '')
    setParsed(null)
    setGroup(request.list ?? 'none')
    setListName('')
    setWatch(false)
    setTags('')
    setNote('')
    setTlp('amber')
    setExpires('')
    setCheck(true)
    setShowUnknown(false)
    setError(null)
  }, [request])

  // Read the text a moment after the last keystroke.
  useEffect(() => {
    if (!request) return undefined
    if (!text.trim()) {
      setParsed(null)
      return undefined
    }
    const id = ++requestRef.current
    const timer = setTimeout(() => {
      setReading(true)
      api
        .post('/iocs/parse', { text })
        .then((result) => id === requestRef.current && (setParsed(result), setError(null)))
        .catch((err) => id === requestRef.current && setError(err.message))
        .finally(() => id === requestRef.current && setReading(false))
    }, 350)
    return () => clearTimeout(timer)
  }, [request, text])

  if (!request) return null
  const summary = parsed?.summary
  const found = parsed?.items.length ?? 0
  // A MISP event names itself: offered as the list's name, not imposed.
  const suggested = parsed?.lists?.[0] ?? (fileName ? fileName.replace(/\.[^.]+$/, '') : '')

  const readFile = async (file) => {
    if (!file) return
    if (file.size > INDICATOR_FILE_MAX_BYTES) {
      setError('The file is larger than 5 MB.')
      return
    }
    setFileName(file.name)
    setText(await file.text())
  }

  const save = async () => {
    setBusy(true)
    setError(null)
    try {
      const fromFile = Boolean(fileName) || request.origin === 'import'
      const body = {
        text,
        tags: tags.split(/[\s,;]+/).filter(Boolean),
        note: found === 1 ? note : '',
        tlp,
        ...(expires ? { expires } : {}),
        check,
        origin: fromFile ? 'import' : 'manual',
      }
      if (group === 'new') body.list = { name: (listName || suggested).trim(), tlp, watch }
      else if (group !== 'none') body.list = { id: group }
      onSaved(await api.post('/iocs', body))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }
  const canSave = found > 0 && !busy && !reading && (group !== 'new' || (listName || suggested).trim())

  return (
    <Modal
      open
      onClose={onClose}
      title="Add indicators"
      maxWidth="max-w-4xl"
      footer={
        <div className="flex w-full flex-wrap items-center justify-between gap-2">
          <span className="text-xs text-fg-muted">
            {request.onNotIndicators && (
              <button
                type="button"
                onClick={request.onNotIndicators}
                className="underline decoration-dotted underline-offset-2 hover:text-fg"
              >
                Not indicators? Place the file in a tab
              </button>
            )}
          </span>
          <span className="flex gap-2">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button disabled={!canSave} onClick={save}>
              {busy ? 'Saving…' : found === 1 ? 'Save 1 indicator' : `Save ${found} indicators`}
            </Button>
          </span>
        </div>
      }
    >
      <div
        className="grid gap-5 md:grid-cols-2"
        onDragOver={(event) => event.preventDefault()}
        onDrop={(event) => {
          event.preventDefault()
          const file = event.dataTransfer.files?.[0]
          if (file) readFile(file)
          else setText((current) => `${current}${current ? '\n' : ''}${event.dataTransfer.getData('text/plain')}`)
        }}
      >
        <section className="min-w-0 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">
              One or many: type, paste or drop a file
            </h3>
            <Button size="xs" variant="secondary" icon={FileUp} onClick={() => fileInput.current?.click()}>
              Choose a file
            </Button>
            <input
              ref={fileInput}
              type="file"
              hidden
              aria-label="File of indicators"
              accept=".txt,.csv,.tsv,.json,.stix,.ioc,.list,text/plain,text/csv,application/json"
              onChange={(event) => {
                readFile(event.target.files?.[0])
                event.target.value = ''
              }}
            />
          </div>
          <textarea
            autoFocus
            aria-label="Indicators"
            value={text}
            spellCheck={false}
            onChange={(event) => {
              setText(event.target.value)
              setFileName('')
            }}
            placeholder={'185.220.101[.]47\nhxxps://cdn-update[.]top/get.php\nevil.example.org\n<sha256>'}
            className={`${INPUT} h-56 w-full resize-y leading-relaxed`}
          />
          <p className="text-xs text-fg-subtle">
            {fileName ? (
              <>
                From <span className="font-mono text-fg-muted">{fileName}</span>.{' '}
              </>
            ) : null}
            Defanged values (hxxp, [.]) are read as they are meant; the type is recognised by itself. Text, CSV, STIX
            2.1, MISP and Nik&apos;s JSON are understood.
          </p>
        </section>

        <section className="min-w-0 space-y-3" aria-label="What Nik found">
          <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">
            What Nik found {parsed && <span className="normal-case">· {FORMATS[parsed.format] ?? parsed.format}</span>}
          </h3>
          {!summary ? (
            <p className="text-sm text-fg-muted">{reading ? 'Reading…' : 'Nothing yet.'}</p>
          ) : (
            <>
              <ul>
                <Row label="New indicators" value={summary.new} />
                <Row label="Already in the library" hint="(kept as they are)" value={summary.known} />
                <Row label="Repeated" value={summary.repeated} />
                <Row label="Private or allowlisted" hint="(saved, never sent out)" value={summary.neverSent} />
                <li className="flex items-baseline justify-between gap-3 py-1.5 text-sm">
                  <span>
                    Not recognised{' '}
                    {summary.unrecognised > 0 && (
                      <button
                        type="button"
                        onClick={() => setShowUnknown((shown) => !shown)}
                        className="text-xs text-link underline-offset-2 hover:underline"
                      >
                        {showUnknown ? 'hide' : 'show'}
                      </button>
                    )}
                  </span>
                  <b className="font-mono tabular-nums">{summary.unrecognised}</b>
                </li>
              </ul>
              {showUnknown && (
                <pre className="max-h-24 overflow-auto border border-line bg-canvas p-2 font-mono text-[11px] text-fg-muted">
                  {parsed.unrecognised.join('\n')}
                </pre>
              )}
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(summary.types).map(([type, count]) => (
                  <Badge key={type}>
                    {type} {count}
                  </Badge>
                ))}
              </div>
            </>
          )}
        </section>

        <section className="min-w-0 space-y-2">
          <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">Group them in a list?</h3>
          <Select
            className="w-full"
            value={group}
            onChange={setGroup}
            options={[
              { value: 'none', label: 'No: save them one by one' },
              { value: 'new', label: 'Yes: a new list…' },
              ...lists.map((list) => ({ value: list.id, label: `Yes: add to "${list.name}"` })),
            ]}
          />
          {group === 'new' && (
            <>
              <input
                aria-label="New list name"
                value={listName}
                maxLength={120}
                placeholder={suggested || 'name of the list'}
                onChange={(event) => setListName(event.target.value)}
                className={`${INPUT} w-full`}
              />
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={watch} onChange={(event) => setWatch(event.target.checked)} />
                Alert me when an incident holds one of them
              </label>
            </>
          )}
        </section>

        <section className="min-w-0 space-y-2">
          <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">For all of them</h3>
          <div className="flex flex-wrap items-center gap-2">
            <input
              aria-label="Tags"
              value={tags}
              placeholder="tags"
              onChange={(event) => setTags(event.target.value)}
              className={`${INPUT} min-w-0 flex-1`}
            />
            <Select value={tlp} onChange={setTlp} options={TLP_OPTIONS} />
          </div>
          {found === 1 && (
            <input
              aria-label="Note"
              value={note}
              maxLength={2000}
              placeholder="note"
              onChange={(event) => setNote(event.target.value)}
              className={`${INPUT} w-full`}
            />
          )}
          <label className="flex items-center gap-2 text-sm">
            <span className="text-fg-muted">Expires on</span>
            <input
              type="date"
              aria-label="Expires on"
              value={expires}
              onChange={(event) => setExpires(event.target.value)}
              className={INPUT}
            />
            <span className="text-xs text-fg-subtle">optional</span>
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={check} onChange={(event) => setCheck(event.target.checked)} />
            Check them when saved
          </label>
        </section>
      </div>
      {error && (
        <p role="alert" className="mt-3 font-mono text-xs text-high">
          {error}
        </p>
      )}
    </Modal>
  )
}
