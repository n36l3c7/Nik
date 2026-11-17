import { useEffect, useMemo, useState } from 'react'
import { useAutomation } from '../../context/AutomationContext.jsx'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { api } from '../../services/api.js'
import { inputValues, runnable } from '../../domain/automation/runs.js'
import { Button, Modal } from '../ui/index.js'

/*
 * "Run a playbook…": choose the playbook, what it runs on, what it is given,
 * and whether it is a dry run.
 *
 * Opened from an incident (its right-click menu, its Automation tab): the
 * incident is set, the playbook is chosen among those that can be run by
 * hand. Opened from a playbook's page: the playbook is set, the incident is
 * chosen (or none).
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
  const { incidents } = useIncidents()
  const { showToast } = useToast()
  const open = runRequest !== null

  const [playbooks, setPlaybooks] = useState(null)
  const [playbookId, setPlaybookId] = useState('')
  const [incidentId, setIncidentId] = useState('')
  const [dryRun, setDryRun] = useState(false)
  const [inputs, setInputs] = useState([]) // what the chosen playbook declares
  const [typed, setTyped] = useState({})
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!runRequest) return undefined
    let alive = true
    setPlaybooks(null)
    setError(null)
    setTyped({})
    setDryRun(Boolean(runRequest.dryRun))
    setPlaybookId(runRequest.playbookId ?? '')
    setIncidentId(runRequest.incidentId ?? '')
    api
      .get('/automation/playbooks')
      .then((found) => alive && setPlaybooks(found.playbooks))
      .catch((failure) => alive && setError(failure.message))
    return () => {
      alive = false
    }
  }, [runRequest])

  const choices = useMemo(() => runnable(playbooks, { dry: dryRun }), [playbooks, dryRun])
  // The choice follows what can be chosen: the first one when none is, none when it is no longer there.
  useEffect(() => {
    if (!open || !playbooks) return
    if (!choices.some((playbook) => playbook.id === playbookId)) setPlaybookId(choices[0]?.id ?? '')
  }, [open, playbooks, choices, playbookId])

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
        objectKind: incidentId ? 'incident' : '',
        objectId: incidentId,
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

  const chosen = choices.find((playbook) => playbook.id === playbookId)
  return (
    <Modal
      open={open}
      onClose={closeRun}
      title="Run a playbook"
      footer={
        <>
          <Button variant="secondary" onClick={closeRun}>
            Cancel
          </Button>
          <Button type="submit" form="form-run-playbook" disabled={busy || !playbookId}>
            {dryRun ? 'Start the dry run' : 'Run'}
          </Button>
        </>
      }
    >
      <form id="form-run-playbook" onSubmit={submit} className="flex flex-col gap-4 text-sm">
        <label className="flex flex-col gap-1" htmlFor="run-playbook">
          <span className="text-fg-muted">Playbook</span>
          <select
            id="run-playbook"
            value={playbookId}
            disabled={!playbooks || choices.length === 0}
            onChange={(event) => setPlaybookId(event.target.value)}
            className={`${FIELD} cursor-pointer`}
          >
            {!playbooks && <option value="">Loading…</option>}
            {playbooks && choices.length === 0 && <option value="">No playbook can be run this way</option>}
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

        <label className="flex flex-col gap-1" htmlFor="run-incident">
          <span className="text-fg-muted">On</span>
          <select
            id="run-incident"
            value={incidentId}
            onChange={(event) => setIncidentId(event.target.value)}
            className={`${FIELD} cursor-pointer`}
          >
            <option value="">nothing (no incident)</option>
            {incidents.map((incident) => (
              <option key={incident.id} value={incident.id}>
                {incident.name}
              </option>
            ))}
          </select>
        </label>

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
