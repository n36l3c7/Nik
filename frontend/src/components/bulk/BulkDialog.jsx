import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { useFields } from '../../context/FieldsContext.jsx'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { runnable } from '../../domain/automation/runs.js'
import { canConfirm, closeAsk, confirmBody, counted, jobClean, planWords, resultWords } from '../../domain/bulk.js'
import { fromInput, toInput } from '../../domain/fields.js'
import { parseTags } from '../../domain/iocLibrary.js'
import { planBulk, runBulk } from '../../lib/bulk.js'
import { useUnsavedChanges } from '../../lib/unsaved.js'
import { api } from '../../services/api.js'
import FieldInput from '../fields/FieldInput.jsx'
import { Button, Modal, Select, Wait } from '../ui/index.js'
import IncidentPicker from '../ui/IncidentPicker.jsx'

/*
 * The dialog of a bulk action: what the action needs to be told, then what
 * it would do, then the button that starts it.
 *
 * `request.form` says what is asked first:
 *
 *   (none)                              nothing: `request.params` is sent as it is
 *   { kind: 'tags' }                    tags to add, tags to take off
 *   { kind: 'choice', label, options,   one value among several; `params(value)` makes
 *     params }                          what is sent
 *   { kind: 'close', rows }             the reason and the notes of a closing, and what the
 *                                       type wants filled when the rows are of one type
 *   { kind: 'field' }                   a field of the registry and its value
 *   { kind: 'playbook' }                a playbook that runs by hand on an incident
 *   { kind: 'incident', params }        an incident, chosen by typing
 *   { kind: 'date' }                    a day, or none
 *
 * As soon as what is asked is filled in, the server says what the action would
 * do (POST …/bulk/plan): how many rows, how many it applies to, what it sets
 * in motion. Nothing is done before "Confirm"; an action that cannot be
 * undone waits for its words to be typed.
 */

const INPUT =
  'h-9 w-full border border-line bg-canvas px-3 font-mono text-sm text-fg placeholder:text-fg-subtle ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const LABEL = 'mb-1 block text-xs font-medium text-fg-muted'
const NOTES = { name: 'close_notes', label: 'Notes', type: 'long_text' }

/** The form of each kind: holds what is typed in `typed`, and says what it comes to with `paramsOf`. */
function Asked({ form, typed, setTyped, extra }) {
  const set = (name) => (value) => setTyped((current) => ({ ...current, [name]: value }))
  switch (form?.kind) {
    case 'tags':
      return (
        <>
          <label className="block">
            <span className={LABEL}>Add these tags</span>
            <input
              type="text"
              autoFocus
              value={typed.add ?? ''}
              placeholder="campaign-q4, c2"
              onChange={(event) => set('add')(event.target.value)}
              className={INPUT}
            />
          </label>
          <label className="block">
            <span className={LABEL}>Take these tags off</span>
            <input
              type="text"
              value={typed.remove ?? ''}
              onChange={(event) => set('remove')(event.target.value)}
              className={INPUT}
            />
          </label>
        </>
      )
    case 'choice':
      return (
        <Select
          label={form.label}
          value={typed.value ?? ''}
          onChange={set('value')}
          options={[{ value: '', label: 'Choose…' }, ...form.options]}
          className="w-full"
        />
      )
    case 'playbook':
      return extra.playbooks === null ? (
        <Wait>Loading the playbooks…</Wait>
      ) : extra.playbooks.length === 0 ? (
        <p className="text-fg-muted">No playbook is made to be run by hand on an incident.</p>
      ) : (
        <Select
          label="Playbook"
          value={typed.value ?? ''}
          onChange={set('value')}
          options={[
            { value: '', label: 'Choose…' },
            ...extra.playbooks.map((playbook) => ({ value: playbook.id, label: playbook.name })),
          ]}
          className="w-full"
        />
      )
    case 'incident':
      return (
        <label className="block" htmlFor="bulk-incident">
          <span className={LABEL}>Incident</span>
          <IncidentPicker
            id="bulk-incident"
            incidents={extra.incidents}
            value={typed.value ?? ''}
            onChange={set('value')}
          />
        </label>
      )
    case 'date':
      return (
        <>
          <label className="block">
            <span className={LABEL}>Delete them on</span>
            <input
              type="date"
              value={typed.value ?? ''}
              disabled={Boolean(typed.none)}
              onChange={(event) => set('value')(event.target.value)}
              className={INPUT}
            />
          </label>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={Boolean(typed.none)}
              onChange={(event) => set('none')(event.target.checked)}
              className="accent-accent"
            />
            No date: take the expiry away
          </label>
        </>
      )
    case 'field': {
      const field = extra.settable.find((item) => item.name === typed.name) ?? null
      return (
        <>
          <Select
            label="Field"
            value={typed.name ?? ''}
            onChange={(name) => setTyped({ name, value: '' })}
            options={[
              { value: '', label: 'Choose…' },
              ...extra.settable.map((item) => ({ value: item.name, label: item.label })),
            ]}
            className="w-full"
          />
          {field && (
            <label className="block" htmlFor="bulk-field-value">
              <span className={LABEL}>{field.label}: the value for all of them (empty clears it)</span>
              <FieldInput
                id="bulk-field-value"
                field={field}
                value={typed.value ?? toInput(field, null)}
                onChange={set('value')}
              />
            </label>
          )}
        </>
      )
    }
    case 'close': {
      const { ask, known } = extra
      const reason = {
        name: 'close_reason',
        label: 'Reason',
        type: ask.reasons.length ? 'choice' : 'text',
        options: { choices: ask.reasons },
      }
      return (
        <>
          <label className="block" htmlFor="bulk-close-reason">
            <span className={LABEL}>Reason</span>
            <FieldInput
              id="bulk-close-reason"
              field={reason}
              value={typed.close_reason ?? ''}
              onChange={set('close_reason')}
            />
          </label>
          {ask.wanted
            .filter((name) => known[name])
            .map((name) => (
              <label key={name} className="block" htmlFor={`bulk-close-${name}`}>
                <span className={LABEL}>
                  {known[name].label} <span className="text-med">· required</span>
                </span>
                <FieldInput
                  id={`bulk-close-${name}`}
                  field={known[name]}
                  value={typed[name] ?? toInput(known[name], null)}
                  onChange={set(name)}
                />
              </label>
            ))}
          <label className="block" htmlFor="bulk-close-notes">
            <span className={LABEL}>Notes</span>
            <FieldInput
              id="bulk-close-notes"
              field={NOTES}
              value={typed.close_notes ?? ''}
              onChange={set('close_notes')}
            />
          </label>
          {ask.mixed && (
            <p className="text-xs text-fg-muted">
              These incidents are of several types. One whose type wants a field filled to close, or does not have this
              reason, is refused and stays open: the result says which.
            </p>
          )}
        </>
      )
    }
    default:
      return null
  }
}

/** What is sent for what was typed: `{ params }`, or `{ error }` (a sentence, '' while nothing is typed). */
function paramsOf(request, typed, extra) {
  const form = request.form
  try {
    switch (form?.kind) {
      case 'tags': {
        const add = parseTags(typed.add)
        const remove = parseTags(typed.remove)
        const wrong = [...add.wrong, ...remove.wrong]
        if (wrong.length) return { error: `Not a tag: ${wrong.join(', ')}` }
        if (!add.tags.length && !remove.tags.length) return { error: '' }
        return { params: { add: add.tags, remove: remove.tags } }
      }
      case 'choice':
      case 'playbook':
      case 'incident':
        if (!typed.value) return { error: '' }
        return { params: form.params ? form.params(typed.value) : { [form.kind]: typed.value } }
      case 'date':
        if (typed.none) return { params: { expiresAt: null } }
        return typed.value ? { params: { expiresAt: typed.value } } : { error: '' }
      case 'field': {
        const field = extra.settable.find((item) => item.name === typed.name)
        if (!field) return { error: '' }
        return { params: { changes: { [field.name]: fromInput(field, typed.value ?? '') } } }
      }
      case 'close': {
        const changes = { status: 'closed' }
        const reason = String(typed.close_reason ?? '').trim()
        if (reason) changes.close_reason = reason
        const notes = String(typed.close_notes ?? '').trim()
        if (notes) changes.close_notes = notes
        for (const name of extra.ask.wanted) {
          const field = extra.known[name]
          if (!field) continue
          const value = fromInput(field, typed[name] ?? '')
          if (value === null) return { error: `${field.label} is needed to close` }
          changes[name] = value
        }
        return { params: { changes } }
      }
      default:
        return { params: request.params ?? {} }
    }
  } catch (failure) {
    return { error: failure.message }
  }
}

/**
 * @param {{
 *   request: object,                       // what useBulk().askBulk() was given
 *   onClose: () => void,
 *   onResult: (job: object) => void,       // show "What it did"
 * }} props
 */
export default function BulkDialog({ request, onClose, onResult }) {
  const { showToast } = useToast()
  const { incidents } = useIncidents()
  const { known, types } = useFields()
  const [typed, setTyped] = useState({})
  const [phrase, setPhrase] = useState('')
  const [plan, setPlan] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [again, setAgain] = useState(0)
  const [playbooks, setPlaybooks] = useState(null)
  const [settable, setSettable] = useState([])
  const kind = request.form?.kind ?? null
  const unsaved = useUnsavedChanges(
    Object.values(typed).some((value) => String(value ?? '').trim() !== '' && value !== false),
    { what: 'What was typed for the action' },
  )

  useEffect(() => {
    let alive = true
    if (kind === 'playbook') {
      api
        .get('/automation/playbooks')
        .then((found) => alive && setPlaybooks(runnable(found.playbooks, { on: 'incident' })))
        .catch((failure) => alive && (setPlaybooks([]), setError(failure.message)))
    }
    if (kind === 'field') {
      api
        .get('/bulk/fields')
        .then((found) => alive && setSettable(found.fields))
        .catch((failure) => alive && setError(failure.message))
    }
    return () => {
      alive = false
    }
  }, [kind])

  const extra = useMemo(
    () => ({
      playbooks,
      settable,
      incidents,
      known,
      ask: kind === 'close' ? closeAsk(request.form.rows ?? [], types) : null,
    }),
    [playbooks, settable, incidents, known, types, kind, request.form],
  )
  const asked = useMemo(() => paramsOf(request, typed, extra), [request, typed, extra])
  const sent = asked.params ? JSON.stringify(asked.params) : null

  // What the server says the action would do, asked again whenever what is sent changes.
  useEffect(() => {
    setPlan(null)
    if (sent === null) return undefined
    let alive = true
    const timer = setTimeout(() => {
      planBulk(request.list, { action: request.action, params: JSON.parse(sent), ...request.selection })
        .then((found) => alive && (setPlan(found), setError(null)))
        .catch((failure) => alive && setError(failure.message))
    }, 250)
    return () => {
      alive = false
      clearTimeout(timer)
    }
  }, [request, sent, again])

  const words = plan ? planWords(plan) : null
  const ready = Boolean(plan) && canConfirm(plan, phrase) && !busy

  const confirm = async (event) => {
    event?.preventDefault()
    if (!ready) return
    setBusy(true)
    setError(null)
    const byQuery = 'query' in request.selection
    try {
      const job = await runBulk(
        request.list,
        {
          action: request.action,
          params: asked.params,
          ...request.selection,
          confirm: confirmBody(plan, phrase, byQuery),
        },
        {
          // In the background: the tray shows it from here on, and the dialog is in nobody's way.
          onStarted: (started) => {
            // The server has it: the selection was acted on, and the list unticks it.
            request.onStarted?.(started)
            if (started.state !== 'running') return
            showToast({ message: `${started.label}: started. Its progress is at the foot of the window.` })
            onClose()
          },
        },
      )
      onClose()
      request.onDone?.(job)
      if (jobClean(job)) showToast({ message: `${job.label}: ${resultWords(job)}.` })
      else onResult(job)
    } catch (failure) {
      // The selection changed meanwhile, or the words are wrong: said, and the plan is read again.
      setError(failure.message)
      setBusy(false)
      setAgain((count) => count + 1)
    }
  }

  return (
    <Modal
      open
      onClose={() => unsaved.leave(onClose)}
      title={request.title}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            form="form-bulk"
            variant={plan?.typed ? 'danger' : 'primary'}
            waiting={busy}
            disabled={!ready}
          >
            {busy ? 'Working…' : 'Confirm'}
          </Button>
        </>
      }
    >
      <form id="form-bulk" onSubmit={confirm} className="flex flex-col gap-3 text-sm">
        <Asked form={request.form} typed={typed} setTyped={setTyped} extra={extra} />
        {asked.error && (
          <p role="alert" className="text-high-fg">
            {asked.error}
          </p>
        )}
        {sent !== null && !plan && !error && <Wait>Counting what this would do…</Wait>}
        {plan && (
          <div aria-label="What this will do" className="flex flex-col gap-2 border-t border-line-soft pt-3">
            <p className="font-semibold text-fg">This will: {plan.label}.</p>
            {words.lines.map((line) => (
              <p key={line} className="text-fg-muted">
                {line}
              </p>
            ))}
            {words.problem && (
              <p
                role="alert"
                className="flex items-start gap-2 border border-high-line bg-high-soft px-3 py-2 text-high-fg"
              >
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                {words.problem}
              </p>
            )}
            {!words.problem && words.typed && (
              <label className="flex flex-col gap-1" htmlFor="bulk-typed">
                <span>
                  This changes {counted(plan.count, plan.list)}, and is asked for twice. To confirm, type{' '}
                  <span className="font-mono text-fg">{words.typed}</span>
                </span>
                <input
                  id="bulk-typed"
                  type="text"
                  value={phrase}
                  autoComplete="off"
                  spellCheck={false}
                  onChange={(event) => setPhrase(event.target.value)}
                  className={INPUT}
                />
              </label>
            )}
            <p className="text-xs text-fg-muted">Each change is written in the audit log, with your name.</p>
          </div>
        )}
        {error && (
          <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-high-fg">
            {error}
          </p>
        )}
      </form>
    </Modal>
  )
}
