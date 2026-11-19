import { useEffect, useMemo, useState } from 'react'
import { useAutomation } from '../../context/AutomationContext.jsx'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { api } from '../../services/api.js'
import { objectName } from '../../domain/automation/catalog.js'
import { inputValues, runnable } from '../../domain/automation/runs.js'
import { Button, Modal } from '../ui/index.js'
import IncidentPicker from '../ui/IncidentPicker.jsx'

/*
 * "Run a playbook…": choose the playbook, what it runs on, what it is given,
 * and whether it is a dry run.
 *
 * Opened from an incident (its right-click menu, its work plan): the
 * incident is set, the playbook is chosen among those that can be run by
 * hand. Opened from a playbook (its page, its row): it runs that playbook and
 * no other, and the incident is found by typing its title or its number. Opened from an analysed e-mail, file or address, or from
 * an indicator: that object is set, and the playbooks offered are those that
 * run on it (their event is about it) or on anything (they have no event).
 *
 * A dry run sends nothing outside Nik and changes nothing in it: each step
 * shows what it would have done. Any playbook with a version can be tried
 * this way, also one that is not meant to be run by hand.
 */

const FIELD =
  'w-full border border-line bg-canvas px-3 py-1.5 text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/**
 * @param {{ onStarted: (run: object) => void }} props  what to do with the run that started (open its page)
 */
export default function RunPlaybookDialog({ onStarted }) {
  const { runRequest, closeRun } = useAutomation()
  // The dialog lives only while it is open: every request starts from its own choices.
  return runRequest ? <OpenDialog runRequest={runRequest} closeRun={closeRun} onStarted={onStarted} /> : null
}

function OpenDialog({ runRequest, closeRun, onStarted }) {
  const { incidents } = useIncidents()
  const { showToast } = useToast()
  const open = true

  const [playbooks, setPlaybooks] = useState(null)
  const [playbookId, setPlaybookId] = useState(runRequest.playbookId ?? '')
  // Opened from a playbook: it is the one that runs, and no other is offered.
  const fixed = Boolean(runRequest.playbookId)
  const [incidentId, setIncidentId] = useState(runRequest.incidentId ?? '')
  const [dryRun, setDryRun] = useState(Boolean(runRequest.dryRun))
  // An artifact or an indicator the dialog was opened on: it is not chosen here.
  const object = runRequest.object ?? null
  const on = object ? object.what : incidentId ? 'incident' : ''
  const [inputs, setInputs] = useState([]) // what the chosen playbook declares
  const [typed, setTyped] = useState({})
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let alive = true
    api
      .get('/automation/playbooks')
      .then((found) => alive && setPlaybooks(found.playbooks))
      .catch((failure) => alive && setError(failure.message))
    return () => {
      alive = false
    }
  }, [])

  const choices = useMemo(() => runnable(playbooks, { dry: dryRun, on }), [playbooks, dryRun, on])
  // The choice follows what can be chosen: the first one when none is, none when it is no longer there.
  useEffect(() => {
    if (!open || !playbooks || fixed) return
    if (!choices.some((playbook) => playbook.id === playbookId)) setPlaybookId(choices[0]?.id ?? '')
  }, [open, playbooks, choices, playbookId, fixed])

  // What the chosen playbook asks for.
  useEffect(() => {
    if (!open || !playbookId) {
      setInputs([])
      return undefined
    }
    let alive = true
    api
      .get(`/automation/playbooks/${encodeURIComponent(playbookId)}`)
      .then((found) => alive && setInputs(Array.isArray(found.graph?.inputs) ? found.graph.inputs : []))
      .catch(() => alive && setInputs([]))
    return () => {
      alive = false
    }
  }, [open, playbookId])

  const submit = async (event) => {
    event.preventDefault()
    setError(null)
    let values
    try {
      values = inputValues(inputs, typed)
    } catch (failure) {
      setError(failure.message)
      return
    }
    setBusy(true)
    try {
      const run = await api.post(`/automation/playbooks/${encodeURIComponent(playbookId)}/run`, {
        objectKind: object ? object.kind : incidentId ? 'incident' : '',
        objectId: object ? object.id : incidentId,
        dryRun,
        inputs: values,
      })
      closeRun()
      showToast({ message: dryRun ? 'The dry run started.' : 'The playbook started.' })
      onStarted(run)
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  const chosen = (fixed ? playbooks : choices)?.find((playbook) => playbook.id === playbookId)
  // A playbook that is not meant to be run by hand can still be tried.
  const cannot = fixed && chosen && !dryRun && !choices.some((playbook) => playbook.id === playbookId)
  return (
    <Modal
      open={open}
      onClose={closeRun}
      title={fixed && chosen ? `Run “${chosen.name}”` : 'Run a playbook'}
      footer={
        <>
          <Button variant="secondary" onClick={closeRun}>
            Cancel
          </Button>
          <Button type="submit" form="form-run-playbook" disabled={busy || !playbookId || cannot}>
            {dryRun ? 'Start the dry run' : 'Run'}
          </Button>
        </>
      }
    >
      <form id="form-run-playbook" onSubmit={submit} className="flex flex-col gap-4 text-sm">
        {fixed && (
          <p className="text-fg-muted">
            {chosen?.description || 'This playbook, on the incident you choose, or on nothing.'}
            {cannot && (
              <span className="mt-1 block text-med">
                Its trigger does not say “Can be run by hand”: it can be tried as a dry run.
              </span>
            )}
          </p>
        )}
        <label className={`flex flex-col gap-1 ${fixed ? 'hidden' : ''}`} htmlFor="run-playbook">
          <span className="text-fg-muted">Playbook</span>
          <select
            id="run-playbook"
            value={playbookId}
            disabled={!playbooks || choices.length === 0}
            onChange={(event) => setPlaybookId(event.target.value)}
            className={`${FIELD} cursor-pointer`}
          >
            {!playbooks && <option value="">Loading…</option>}
            {playbooks && choices.length === 0 && (
              <option value="">
                {on ? `No playbook can be run on ${objectName(on)}` : 'No playbook can be run this way'}
              </option>
            )}
            {choices.map((playbook) => (
              <option key={playbook.id} value={playbook.id}>
                {playbook.name}
                {playbook.enabled ? '' : ' (off)'}
              </option>
            ))}
          </select>
          {chosen?.description && <span className="text-xs text-fg-muted">{chosen.description}</span>}
          {playbooks && choices.length === 0 && (
            <span className="text-xs text-fg-muted">
              {dryRun
                ? 'A playbook needs a saved version to be tried.'
                : 'A playbook is run by hand when its trigger says “Can be run by hand” and it has a saved version. Any playbook with a version can be tried as a dry run.'}
            </span>
          )}
        </label>

        {object && (
          <div className="flex flex-col gap-1">
            <span className="text-fg-muted">On</span>
            <span
              id="run-object"
              className="break-all border border-line-soft bg-panel px-3 py-1.5 font-mono text-xs text-fg"
            >
              {objectName(object.what)} · {object.label}
            </span>
          </div>
        )}
        {!object && (
          <div className="flex flex-col gap-1">
            <label className="text-fg-muted" htmlFor="run-incident">
              On which incident
            </label>
            <IncidentPicker id="run-incident" incidents={incidents} value={incidentId} onChange={setIncidentId} />
            {!incidentId && (
              <span className="text-xs text-fg-muted">Leave it empty to run on nothing (no incident).</span>
            )}
          </div>
        )}

        {inputs.length > 0 && (
          <fieldset className="flex flex-col gap-3 border border-line-soft p-3">
            <legend className="px-1 font-mono text-[11px] uppercase tracking-wider text-fg-muted">Inputs</legend>
            {inputs.map((input) => (
              <label key={input.name} className="flex flex-col gap-1" htmlFor={`run-input-${input.name}`}>
                <span className="text-fg-muted">
                  <span className="font-mono text-fg">{input.name}</span> · {input.type ?? 'text'}
                  {input.required ? ' · required' : ''}
                </span>
                {input.type === 'bool' ? (
                  <select
                    id={`run-input-${input.name}`}
                    value={typed[input.name] ?? ''}
                    onChange={(event) => setTyped({ ...typed, [input.name]: event.target.value })}
                    className={`${FIELD} cursor-pointer`}
                  >
                    <option value="">(not given)</option>
                    <option value="true">yes</option>
                    <option value="false">no</option>
                  </select>
                ) : (
                  <input
                    id={`run-input-${input.name}`}
                    type="text"
                    value={typed[input.name] ?? ''}
                    autoComplete="off"
                    spellCheck={false}
                    placeholder={
                      input.type === 'list' ? 'one, two, three' : input.type === 'object' ? '{"key": "value"}' : ''
                    }
                    onChange={(event) => setTyped({ ...typed, [input.name]: event.target.value })}
                    className={`${FIELD} font-mono`}
                  />
                )}
              </label>
            ))}
          </fieldset>
        )}

        <label className="flex items-start gap-2">
          <input
            type="checkbox"
            checked={dryRun}
            onChange={(event) => setDryRun(event.target.checked)}
            className="mt-1 accent-accent"
          />
          <span>
            Dry run
            <span className="block text-xs text-fg-muted">
              Nothing is sent outside Nik and nothing is changed in it: each step shows what it would have done.
              Approvals are taken as given.
            </span>
          </span>
        </label>

        {error && (
          <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-high">
            {error}
          </p>
        )}
      </form>
    </Modal>
  )
}
