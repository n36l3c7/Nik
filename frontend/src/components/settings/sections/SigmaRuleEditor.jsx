import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AlertCircle, ArrowLeft, CheckCircle2, FlaskConical, RotateCcw, Save, Trash2 } from 'lucide-react'
import CodeEditor from '../../automation/CodeEditor.jsx'
import LevelBadge from '../../evidence/LevelBadge.jsx'
import { Badge, Button, Modal, Select, Wait } from '../../ui/index.js'
import IncidentPicker from '../../ui/IncidentPicker.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { useToast } from '../../../context/ToastContext.jsx'
import { diffCounts, lineDiff } from '../../../domain/automation/scripts.js'
import { tagChips } from '../../../domain/detections.js'
import {
  TRY_KINDS,
  changedText,
  cutText,
  errorText,
  errorsOf,
  incidentHref,
  logSourceText,
  positionOf,
  shownMatches,
  starterRule,
  tryText,
} from '../../../domain/sigma.js'
import { useUnsavedChanges } from '../../../lib/unsaved.js'
import { formatDateTime } from '../../../lib/time.js'
import { sigmaRules } from '../../../services/api.js'

/*
 * One Sigma rule in an editor: the YAML on the left, what the worker made of it at the right, the errors
 * under it. The text is read by the worker 400 ms after the last key (nothing is saved by that); Save
 * writes it, and a rule the worker refuses comes back with its lines. "Try on an incident" runs the text
 * as it is on screen over the records of an incident and saves nothing.
 *
 * `ruleId` null is a new rule. `onClose(changed)` goes back to the list.
 */

const VALIDATE_DELAY_MS = 400
const NO_ERRORS = []

const SIDE = 'border border-line bg-panel'

function RuleCard({ info, creating }) {
  return (
    <div className={`${SIDE} space-y-2 p-3 text-sm`}>
      <div className="flex flex-wrap items-center gap-2">
        <LevelBadge level={info.level} />
        <span className="min-w-0 font-semibold text-fg">{info.title || info.id}</span>
        {info.kind === 'correlation' && <Badge color="violet">correlation</Badge>}
      </div>
      <dl className="grid grid-cols-[6rem_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
        <dt className="text-fg-muted">Author</dt>
        <dd className="m-0 break-words">{info.author || 'not named'}</dd>
        <dt className="text-fg-muted">Status</dt>
        <dd className="m-0">{info.status || '—'}</dd>
        <dt className="text-fg-muted">Log source</dt>
        <dd className="m-0 font-mono">{logSourceText(info)}</dd>
        <dt className="text-fg-muted">Id</dt>
        <dd className="m-0 break-all font-mono">{info.id}</dd>
      </dl>
      {tagChips(info.tags).length > 0 && (
        <p className="flex flex-wrap gap-1">
          {tagChips(info.tags).map((tag) => (
            <span key={tag} className="border border-line bg-canvas px-1.5 py-px font-mono text-[11px] text-fg-muted">
              {tag}
            </span>
          ))}
        </p>
      )}
      {info.supported ? (
        <p className="flex items-center gap-1.5 text-xs text-accent">
          <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
          Nik can run this rule.
        </p>
      ) : (
        <p role="status" className="border border-med-line bg-med-soft px-2 py-1.5 text-xs text-med-fg">
          Nik cannot run this rule: {info.reason || 'the worker did not say why'}. It can be saved, and stays off.
        </p>
      )}
      {creating && info.exists && (
        <p role="alert" className="border border-high-line bg-high-soft px-2 py-1.5 text-xs text-high-fg">
          A rule with this id exists already: saving this text will be refused. Change the id.
        </p>
      )}
    </div>
  )
}

function TryPanel({ source, blocked }) {
  const { incidents } = useIncidents()
  const [incidentId, setIncidentId] = useState('')
  const [kind, setKind] = useState('')
  const [state, setState] = useState({ running: false, result: null, error: '' })
  const controller = useRef(null)
  useEffect(() => () => controller.current?.abort(), [])

  const run = async () => {
    controller.current?.abort()
    const mine = new AbortController()
    controller.current = mine
    setState({ running: true, result: null, error: '' })
    try {
      const result = await sigmaRules.tryOn({ source, incidentId, kind }, { signal: mine.signal })
      setState({ running: false, result, error: '' })
    } catch (failure) {
      if (failure?.name === 'AbortError') return
      const errors = errorsOf(failure)
      const detail = errors.length ? errors.map(errorText).join(' ') : failure.message
      setState({ running: false, result: null, error: detail })
    }
  }

  const { result } = state
  const matches = shownMatches(result)
  return (
    <section aria-label="Try on an incident" className={`${SIDE} space-y-3 p-4`}>
      <div>
        <h3 className="flex items-center gap-2 text-sm font-semibold">
          <FlaskConical className="h-4 w-4 text-accent" aria-hidden="true" />
          Try on an incident
        </h3>
        <p className="mt-1 text-xs text-fg-muted">
          Runs the text above, as it is now, over the host records of an incident. Nothing is saved and nothing is
          marked on the incident.
        </p>
      </div>
      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-[16rem] flex-1">
          <label htmlFor="sigma-try-incident" className="mb-1 block text-xs text-fg-muted">
            Incident
          </label>
          <IncidentPicker id="sigma-try-incident" incidents={incidents} value={incidentId} onChange={setIncidentId} />
        </div>
        <Select value={kind} onChange={setKind} options={TRY_KINDS} label="Section" />
        <Button
          icon={FlaskConical}
          variant="secondary"
          waiting={state.running}
          disabled={!incidentId || state.running || blocked}
          onClick={run}
        >
          {state.running ? 'Running…' : 'Run'}
        </Button>
      </div>
      {blocked && <p className="text-xs text-fg-muted">Mend the errors of the text first.</p>}
      {state.running && <Wait>Running the rule over the records…</Wait>}
      {state.error && (
        <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
          {state.error}
        </p>
      )}
      {result && (
        <div className="space-y-3" aria-live="polite">
          <p className="text-sm font-medium text-fg">
            {tryText(result)}{' '}
            <span className="font-normal text-fg-muted">
              {result.ran === 0 ? 'No rule of the text could run.' : ''}
              {typeof result.seconds === 'number' ? `${result.seconds.toFixed(1)} s.` : ''}
            </span>
          </p>
          {result.cut && (
            <p role="status" className="border border-med-line bg-med-soft px-3 py-2 text-sm text-med-fg">
              {cutText(result)}
            </p>
          )}
          {(result.notEvaluated ?? []).length > 0 && (
            <div className="text-sm">
              <p className="font-medium text-fg">Not evaluated</p>
              <ul className="m-0 list-disc pl-5 text-fg-muted">
                {result.notEvaluated.map((item) => (
                  <li key={`${item.rule}-${item.reason}`}>
                    <span className="font-mono text-xs">{item.rule}</span>: {item.reason}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {(result.notes ?? []).length > 0 && (
            <ul className="m-0 list-disc pl-5 text-xs text-fg-muted">
              {result.notes.map((note) => (
                <li key={String(note?.reason ?? note)}>
                  {typeof note === 'string' ? note : [note.reason, note.detail].filter(Boolean).join(': ')}
                </li>
              ))}
            </ul>
          )}
          {matches.items.length > 0 && (
            <div className="overflow-x-auto border border-line">
              <table className="w-full text-left text-xs">
                <thead className="bg-raised text-fg-muted">
                  <tr>
                    <th scope="col" className="px-3 py-1.5 font-medium">
                      Time
                    </th>
                    <th scope="col" className="px-3 py-1.5 font-medium">
                      Level
                    </th>
                    <th scope="col" className="px-3 py-1.5 font-medium">
                      Rule
                    </th>
                    <th scope="col" className="px-3 py-1.5 font-medium">
                      Record
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {matches.items.map((match, index) => (
                    <tr
                      key={`${match.recordId ?? match.key}-${match.ruleId}-${index}`}
                      className="border-t border-line-soft align-top"
                    >
                      <td className="whitespace-nowrap px-3 py-1.5 font-mono">
                        {Number.isFinite(match.ts) ? formatDateTime(match.ts) : '—'}
                      </td>
                      <td className="px-3 py-1.5">
                        <LevelBadge level={match.level} empty="—" />
                      </td>
                      <td className="px-3 py-1.5">{match.title || match.ruleId}</td>
                      <td className="max-w-xl break-all px-3 py-1.5 font-mono">
                        {match.summary || match.key}
                        {Array.isArray(match.records) && match.records.length > 0 && (
                          <span className="text-fg-muted"> · {match.records.length} records together</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {matches.more > 0 && (
            <p className="text-xs text-fg-muted">{matches.more.toLocaleString('en-US')} more matches are not listed.</p>
          )}
          {result.matchCount > 0 && (
            <p className="text-xs">
              <a
                href={incidentHref(incidentId)}
                target="_blank"
                rel="noreferrer noopener"
                className="text-link hover:underline"
              >
                Open the incident
              </a>{' '}
              <span className="text-fg-muted">
                and read these records in its host pages (Event Logs, Endpoint, Browser, Command History).
              </span>
            </p>
          )}
        </div>
      )}
    </section>
  )
}

export default function SigmaRuleEditor({ ruleId, canManage, onClose }) {
  const { showToast } = useToast()
  const creating = ruleId === null
  const [rule, setRule] = useState(null) // the stored rule, whole (not for a new one)
  const [loadError, setLoadError] = useState('')
  const [starter] = useState(() => (creating ? starterRule() : ''))
  const [text, setText] = useState(starter)
  const [saved, setSaved] = useState(() => (creating ? starter : null)) // the text as the server holds it (null: not read yet)
  const [checked, setChecked] = useState({ text: null, answer: null, error: '' }) // the answer of /validate
  const [refused, setRefused] = useState({ text: null, errors: NO_ERRORS }) // the lines a save came back with
  const [busy, setBusy] = useState('') // 'save' | 'delete' | 'reset'
  const [dialog, setDialog] = useState('') // 'delete' | 'reset'
  const view = useRef(null)
  const readOnly = !canManage

  // The rule, for an existing one.
  useEffect(() => {
    if (creating) return undefined
    const controller = new AbortController()
    sigmaRules
      .get(ruleId, { signal: controller.signal })
      .then((found) => {
        setRule(found)
        setText(found.source)
        setSaved(found.source)
      })
      .catch((failure) => {
        if (failure?.name !== 'AbortError') setLoadError(failure.message || 'The rule could not be read.')
      })
    return () => controller.abort()
  }, [ruleId, creating])

  // The worker reads the text a moment after the last key.
  useEffect(() => {
    if (saved === null) return undefined
    const controller = new AbortController()
    const timer = setTimeout(() => {
      sigmaRules
        .validate(text, { signal: controller.signal })
        .then((answer) => setChecked({ text, answer, error: '' }))
        .catch((failure) => {
          if (failure?.name === 'AbortError') return
          setChecked({ text, answer: null, error: failure.message || 'The text could not be checked.' })
        })
    }, VALIDATE_DELAY_MS)
    return () => {
      clearTimeout(timer)
      controller.abort()
    }
  }, [text, saved])

  const current = checked.text === text ? checked : null
  const checking = saved !== null && !current
  const errors = useMemo(() => {
    const own = current?.answer?.errors ?? NO_ERRORS
    const sent = refused.text === text ? refused.errors : NO_ERRORS
    const merged = [...own]
    for (const error of sent) {
      if (!merged.some((item) => item.line === error.line && item.message === error.message)) merged.push(error)
    }
    return merged
  }, [current, refused, text])
  const infos = current?.answer?.rules ?? []
  const dirty = saved !== null && changedText(text, saved)
  const where = rule && rule.pack ? `from the pack ${rule.pack}` : 'written here'

  const save = useCallback(async () => {
    setBusy('save')
    try {
      if (creating) {
        const made = await sigmaRules.create(text)
        showToast({ message: made.rules.length === 1 ? 'Rule saved.' : `${made.rules.length} rules saved.` })
        onClose(true)
        return
      }
      const stored = await sigmaRules.update(ruleId, text)
      setRule(stored)
      setText(stored.source)
      setSaved(stored.source)
      showToast({ message: 'Rule saved.' })
    } catch (failure) {
      const lines = errorsOf(failure)
      setRefused({ text, errors: lines })
      if (lines.length === 0) showToast({ message: failure.message || 'The rule could not be saved.' })
      throw failure
    } finally {
      setBusy('')
    }
  }, [creating, text, ruleId, showToast, onClose])

  const unsaved = useUnsavedChanges(dirty && canManage, {
    what: 'The Sigma rule',
    name: infos[0]?.title || rule?.title || 'new rule',
    save,
  })
  const back = () => unsaved.leave(() => onClose(false))

  const remove = async () => {
    setBusy('delete')
    try {
      await sigmaRules.remove(ruleId)
      showToast({ message: 'Rule deleted.' })
      onClose(true)
    } catch (failure) {
      showToast({ message: failure.message || 'The rule could not be deleted.' })
      setBusy('')
      setDialog('')
    }
  }

  const reset = async () => {
    setBusy('reset')
    try {
      const stored = await sigmaRules.reset(ruleId)
      setRule(stored)
      setText(stored.source)
      setSaved(stored.source)
      showToast({ message: "The pack's text is back." })
    } catch (failure) {
      showToast({ message: failure.message || 'The rule could not be reset.' })
    } finally {
      setBusy('')
      setDialog('')
    }
  }

  const goTo = (error) => {
    const editor = view.current
    if (!editor) return
    const { from } = positionOf(editor.state.doc.toString(), error.line, error.column)
    editor.dispatch({ selection: { anchor: from }, scrollIntoView: true })
    editor.focus()
  }

  const diff = useMemo(
    () => (dialog === 'reset' && rule?.original != null ? lineDiff(rule.source, rule.original) : []),
    [dialog, rule],
  )
  const counts = diffCounts(diff)

  if (loadError) {
    return (
      <section className="space-y-4">
        <Button variant="ghost" size="sm" icon={ArrowLeft} onClick={() => onClose(false)}>
          Sigma rules
        </Button>
        <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
          {loadError}
        </p>
      </section>
    )
  }
  if (saved === null) {
    return (
      <div className="p-2">
        <Wait>Reading the rule…</Wait>
      </div>
    )
  }

  const editable = canManage && !busy
  const canDelete = !creating && rule && rule.pack === '' && canManage
  const canReset = !creating && rule && rule.pack !== '' && rule.edited && canManage
  const title = creating ? 'New rule' : infos[0]?.title || rule?.title || 'Rule'
  const blocked = errors.length > 0 || checking

  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="ghost" size="sm" icon={ArrowLeft} onClick={back}>
          Sigma rules
        </Button>
        <h2 className="min-w-0 flex-1 truncate text-base font-semibold text-fg">{title}</h2>
        {!creating && <span className="text-xs text-fg-muted">{where}</span>}
        {readOnly && <Badge>read only</Badge>}
        {canReset && (
          <Button
            variant="secondary"
            size="sm"
            icon={RotateCcw}
            disabled={Boolean(busy)}
            onClick={() => setDialog('reset')}
          >
            Reset to the pack's text
          </Button>
        )}
        {canDelete && (
          <Button
            variant="secondary"
            size="sm"
            icon={Trash2}
            disabled={Boolean(busy)}
            onClick={() => setDialog('delete')}
          >
            Delete
          </Button>
        )}
        {canManage && (
          <Button
            size="sm"
            icon={Save}
            waiting={busy === 'save'}
            disabled={!dirty || Boolean(busy) || errors.length > 0}
            onClick={() => save().catch(() => {})}
          >
            {creating ? 'Save rule' : 'Save'}
          </Button>
        )}
      </div>

      {rule?.edited && (
        <p className="border border-line bg-panel px-3 py-2 text-xs text-fg-muted">
          This rule of the pack was changed here. An update of the pack leaves it as it is; reset puts the pack's text
          back.
        </p>
      )}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <div className="min-w-0 space-y-3">
          <CodeEditor
            value={text}
            onChange={setText}
            language="yaml"
            label="Sigma rule, YAML"
            readOnly={!editable}
            minHeight="22rem"
            maxHeight="65vh"
            diagnostics={errors}
            viewRef={view}
          />
          <div aria-live="polite" className="text-sm">
            {current?.error && (
              <p role="alert" className="flex items-center gap-2 text-high-fg">
                <AlertCircle className="h-4 w-4 shrink-0" aria-hidden="true" />
                {current.error}
              </p>
            )}
            {errors.length > 0 ? (
              <ul
                aria-label="Errors in the rule"
                className="m-0 list-none space-y-1 border border-high-line bg-high-soft p-2"
              >
                {errors.map((error, index) => (
                  <li key={`${error.line}-${error.column}-${index}`}>
                    <button
                      type="button"
                      onClick={() => goTo(error)}
                      className="w-full text-left text-high-fg hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    >
                      {errorText(error)}
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-fg-muted">
                {checking
                  ? 'Reading the text…'
                  : current?.answer
                    ? 'The worker reads this text without a problem.'
                    : ''}
              </p>
            )}
          </div>
        </div>
        <aside aria-label="What the rule is" className="space-y-3">
          {infos.length === 0 && !checking && errors.length === 0 && (
            <p className="text-sm text-fg-muted">No rule in the text.</p>
          )}
          {infos.map((info) => (
            <RuleCard key={`${info.id}-${info.line}`} info={info} creating={creating} />
          ))}
        </aside>
      </div>

      <TryPanel source={text} blocked={blocked} />

      <Modal
        open={dialog === 'delete'}
        onClose={() => setDialog('')}
        title="Delete this rule?"
        footer={
          <>
            <Button variant="secondary" onClick={() => setDialog('')}>
              Cancel
            </Button>
            <Button variant="danger" waiting={busy === 'delete'} disabled={Boolean(busy)} onClick={remove}>
              Delete the rule
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg-muted">
          The rule is removed and stops running on the files read from now on. The detections it already made stay on
          their records until the file is analysed again.
        </p>
      </Modal>

      <Modal
        open={dialog === 'reset'}
        onClose={() => setDialog('')}
        title="Reset to the pack's text?"
        maxWidth="max-w-3xl"
        footer={
          <>
            <Button variant="secondary" onClick={() => setDialog('')}>
              Cancel
            </Button>
            <Button waiting={busy === 'reset'} disabled={Boolean(busy)} onClick={reset}>
              Put the pack's text back
            </Button>
          </>
        }
      >
        <div className="space-y-3 text-sm">
          <p className="text-fg-muted">
            Your changes to this rule are lost: its text becomes the one the pack gives, and the pack's updates apply to
            it again. {counts.added} {counts.added === 1 ? 'line is' : 'lines are'} added and {counts.removed} removed.
          </p>
          <pre
            tabIndex={0}
            aria-label="Changes the reset makes"
            className="max-h-80 overflow-auto border border-line bg-sunken p-2 font-mono text-xs"
          >
            {diff
              .filter((line) => line.kind !== 'same')
              .map((line, index) => (
                <div key={index} className={line.kind === 'add' ? 'text-accent-fg' : 'text-high-fg'}>
                  {line.kind === 'add' ? '+ ' : '- '}
                  {line.text}
                </div>
              ))}
          </pre>
        </div>
      </Modal>
    </section>
  )
}
