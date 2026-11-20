import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ArrowLeft, Download, FlaskConical, Plus, Trash2 } from 'lucide-react'
import { useAutomation } from '../../context/AutomationContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { api } from '../../services/api.js'
import {
  TYPES,
  diffCounts,
  draftOf,
  draftProblems,
  fieldProblems,
  lineDiff,
  parseJson,
  sameDraft,
} from '../../domain/automation/scripts.js'
import { saveBlob } from '../../lib/download.js'
import { formatDateTime } from '../../lib/time.js'
import { AsciiSkull, Badge, Button, EmptyState, Modal } from '../ui/index.js'
import CodeEditor from './CodeEditor.jsx'
import { SandboxBox } from './ScriptsPage.jsx'
import { INPUT, SectionTitle } from './fields.jsx'
import { useUnsavedChanges } from '../../lib/unsaved.js'

/*
 * ============================================================================
 * A SCRIPT — its code, what it takes and gives, its test, its versions
 * ============================================================================
 *
 * `def main(args)` returns something JSON can hold. The arguments and the
 * outputs declared here are what the node shows on the canvas: the fields to
 * fill, and what later nodes pick.
 *
 * The editor writes a draft that saves itself. "Run the test" runs the draft
 * in the sandbox with the arguments of the test; "Save as version" does the
 * same and, when the test passes, puts the version in the library. A
 * playbook stays on the version it was saved with.
 */

const SAVE_DELAY_MS = 900
const SAVE_TEXT = {
  idle: '',
  pending: 'draft not saved yet',
  saving: 'saving the draft…',
  saved: 'draft saved',
  error: 'the draft was not saved',
}
const TYPE_OPTIONS = TYPES.map((type) => ({ value: type, label: type }))

/** The arguments or the outputs, as a table that is edited in place. */
function Fields({ title, fields, onChange, withRequired }) {
  const problems = fieldProblems(fields)
  const change = (index, patch) => onChange(fields.map((field, at) => (at === index ? { ...field, ...patch } : field)))
  const what = withRequired ? 'Argument' : 'Output'
  return (
    <section aria-label={title} className="flex flex-col gap-2">
      <SectionTitle
        action={
          <Button
            variant="secondary"
            size="xs"
            icon={Plus}
            onClick={() =>
              onChange([
                ...fields,
                { name: '', type: 'text', description: '', ...(withRequired ? { required: false } : {}) },
              ])
            }
          >
            Add
          </Button>
        }
      >
        {title}
      </SectionTitle>
      {fields.length === 0 ? (
        <p className="text-xs text-fg-muted">None.</p>
      ) : (
        <ul className="flex flex-col gap-1.5">
          {fields.map((field, index) => {
            const problem = problems.find((item) => item.index === index)
            return (
              <li
                key={index}
                role="group"
                aria-label={`${what} ${index + 1}`}
                className="flex flex-col gap-1 border border-line-soft p-2"
              >
                <div className="flex flex-wrap items-center gap-1.5">
                  <input
                    type="text"
                    value={field.name ?? ''}
                    aria-label={`${what} ${index + 1}: name`}
                    aria-invalid={problem ? true : undefined}
                    placeholder="name"
                    autoComplete="off"
                    spellCheck={false}
                    maxLength={40}
                    onChange={(event) => change(index, { name: event.target.value })}
                    className={`${INPUT} w-36! ${problem ? 'border-high-line' : ''}`}
                  />
                  <select
                    value={field.type ?? 'any'}
                    aria-label={`${what} ${index + 1}: type`}
                    onChange={(event) => change(index, { type: event.target.value })}
                    className={`${INPUT} w-28! cursor-pointer`}
                  >
                    {TYPE_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                  {withRequired && (
                    <label className="flex items-center gap-1 text-xs text-fg-muted">
                      <input
                        type="checkbox"
                        checked={Boolean(field.required)}
                        onChange={(event) => change(index, { required: event.target.checked })}
                        className="accent-accent"
                      />
                      required
                    </label>
                  )}
                  <Button
                    variant="ghost"
                    size="xs"
                    icon={Trash2}
                    className="ml-auto"
                    aria-label={`Remove ${what.toLowerCase()} ${index + 1}`}
                    onClick={() => onChange(fields.filter((_, at) => at !== index))}
                  />
                </div>
                <input
                  type="text"
                  value={field.description ?? ''}
                  aria-label={`${what} ${index + 1}: description`}
                  placeholder="what it is, for who fills the node"
                  maxLength={300}
                  onChange={(event) => change(index, { description: event.target.value })}
                  className={`${INPUT} font-sans`}
                />
                {problem && (
                  <p role="alert" className="text-xs text-high-fg">
                    {problem.message}
                  </p>
                )}
              </li>
            )
          })}
        </ul>
      )}
    </section>
  )
}

/** What a test gave: passed or not, the result, what the script printed. */
function TestResult({ result }) {
  if (!result) return null
  return (
    <div
      role="status"
      aria-label="Result of the test"
      className={[
        'flex flex-col gap-2 border p-2 text-xs',
        result.passed ? 'border-accent-strong bg-accent-soft/40' : 'border-high-line bg-high-soft',
      ].join(' ')}
    >
      <p className="flex flex-wrap items-center gap-2">
        <Badge color={result.passed ? 'emerald' : 'red'}>{result.passed ? 'passed' : 'failed'}</Badge>
        <span className="font-mono text-fg-muted">{result.durationMs} ms</span>
        {result.error && <span className="min-w-0 break-words text-high-fg">{result.error}</span>}
      </p>
      {result.result !== undefined && result.result !== null && (
        <pre className="max-h-48 overflow-auto border border-line bg-sunken p-2 font-mono text-fg">
          {JSON.stringify(result.result, null, 2)}
        </pre>
      )}
      {result.stdout && (
        <>
          <span className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">Printed</span>
          <pre className="max-h-32 overflow-auto border border-line bg-sunken p-2 font-mono text-fg-muted">
            {result.stdout}
          </pre>
        </>
      )}
    </div>
  )
}

/** An older version: its code, and what the draft changes from it. */
function VersionDialog({ scriptId, number, draftCode, onClose, onRestore }) {
  const [version, setVersion] = useState(null)
  const [error, setError] = useState(null)
  useEffect(() => {
    if (number === null) return undefined
    let alive = true
    setVersion(null)
    setError(null)
    api
      .get(`/automation/scripts/${encodeURIComponent(scriptId)}/versions/${number}`)
      .then((found) => alive && setVersion(found))
      .catch((failure) => alive && setError(failure.message))
    return () => {
      alive = false
    }
  }, [scriptId, number])
  const diff = useMemo(() => (version ? lineDiff(version.code, draftCode) : []), [version, draftCode])
  const counts = diffCounts(diff)
  return (
    <Modal
      open={number !== null}
      onClose={onClose}
      title={`Version ${number}`}
      maxWidth="max-w-4xl"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Close
          </Button>
          <Button disabled={!version} onClick={() => onRestore(version)}>
            Put version {number} back into the draft
          </Button>
        </>
      }
    >
      {error && (
        <p role="alert" className="text-sm text-high-fg">
          {error}
        </p>
      )}
      {!version && !error && (
        <p role="status" className="font-mono text-sm text-fg-muted">
          Loading…
        </p>
      )}
      {version && (
        <div className="flex flex-col gap-3 text-sm">
          <p className="text-fg-muted">
            Saved {formatDateTime(Date.parse(version.createdAt))} by{' '}
            <span className="font-mono">{version.createdBy}</span>. Against the draft:{' '}
            {counts.added === 0 && counts.removed === 0
              ? 'the code is the same.'
              : `${counts.added} lines added, ${counts.removed} removed.`}
          </p>
          <pre
            aria-label={`What the draft changes from version ${number}`}
            className="max-h-[55vh] overflow-auto border border-line bg-sunken p-2 font-mono text-xs leading-relaxed"
          >
            {diff.map((line, index) => (
              <span
                key={index}
                className={[
                  'block whitespace-pre',
                  line.kind === 'add'
                    ? 'bg-accent-soft text-accent-fg'
                    : line.kind === 'remove'
                      ? 'bg-high-soft text-high-fg'
                      : 'text-fg-muted',
                ].join(' ')}
              >
                {line.kind === 'add' ? '+ ' : line.kind === 'remove' ? '- ' : '  '}
                {line.text}
              </span>
            ))}
          </pre>
        </div>
      )}
    </Modal>
  )
}

/**
 * @param {{ id: string, onBack: () => void, onOpenPlaybooks: () => void }} props
 */
export default function ScriptPage({ id, onBack, onOpenPlaybooks }) {
  const { loadCatalog } = useAutomation()
  const { showToast } = useToast()
  const base = `/automation/scripts/${encodeURIComponent(id)}`

  const [script, setScript] = useState(null)
  const [loadError, setLoadError] = useState(null)
  const [draft, setDraft] = useState(null)
  const [argsText, setArgsText] = useState('{}')
  const [expectText, setExpectText] = useState('')
  const [description, setDescription] = useState('')
  const [saveState, setSaveState] = useState('idle')
  const [result, setResult] = useState(null)
  const [testing, setTesting] = useState(false)
  const [saving, setSaving] = useState(false)
  const [shownVersion, setShownVersion] = useState(null)
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [sandbox, setSandbox] = useState(true)

  const savedDraft = useRef(null)
  const latestDraft = useRef(null)
  latestDraft.current = draft

  /** Take what the server has as the script; `resetDraft` also restarts the editor from it. */
  const adopt = useCallback((found, { resetDraft = false } = {}) => {
    setScript(found)
    setDescription(found.description ?? '')
    if (!resetDraft) return
    const next = draftOf(found)
    savedDraft.current = next
    setDraft(next)
    setArgsText(JSON.stringify(next.test.args, null, 2))
    setExpectText('expect' in next.test ? JSON.stringify(next.test.expect, null, 2) : '')
    setSaveState('idle')
  }, [])

  useEffect(() => {
    let alive = true
    setScript(null)
    setDraft(null)
    setResult(null)
    setLoadError(null)
    api
      .get(base)
      .then((found) => alive && adopt(found, { resetDraft: true }))
      .catch((failure) => alive && setLoadError(failure.message))
    api
      .get('/automation/scripts')
      .then((found) => alive && setSandbox(Boolean(found.sandbox)))
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [base, adopt])

  // ---- The draft saves itself -----------------------------------------------
  const saveDraft = useCallback(
    async (next) => {
      setSaveState('saving')
      try {
        const found = await api.put(base, { draft: next })
        savedDraft.current = next
        setScript(found)
        setSaveState(latestDraft.current === next ? 'saved' : 'pending')
      } catch (failure) {
        setSaveState('error')
        showToast({ message: `The draft was not saved: ${failure.message}` })
      }
    },
    [base, showToast],
  )
  useEffect(() => {
    if (!draft || draft === savedDraft.current) return undefined
    setSaveState('pending')
    const timer = setTimeout(() => saveDraft(draft), SAVE_DELAY_MS)
    return () => clearTimeout(timer)
  }, [draft, saveDraft])
  useEffect(
    () => () => {
      const next = latestDraft.current
      if (next && next !== savedDraft.current) api.put(base, { draft: next }).catch(() => {})
    },
    [base],
  )

  const change = useCallback((patch) => setDraft((before) => (before ? { ...before, ...patch } : before)), [])
  const parsedArgs = parseJson(argsText, {})
  const parsedExpect = parseJson(expectText)

  // Nothing unsaved is lost without asking (lib/unsaved.js). The draft saves itself and is sent on the
  // way out, so only the browser's tab closing could lose it; a save the server refused, and a test
  // whose JSON cannot be read (it never reaches the draft), are what leaving would lose.
  useUnsavedChanges(saveState === 'pending' || saveState === 'saving', {
    what: 'The script',
    name: script?.name,
    sent: true,
  })
  useUnsavedChanges(saveState === 'error', {
    what: 'The draft of the script',
    name: script?.name,
    save: () =>
      api.put(base, { draft: latestDraft.current }).then((found) => {
        savedDraft.current = latestDraft.current
        setScript(found)
        setSaveState('saved')
      }),
  })
  useUnsavedChanges(Boolean(draft) && Boolean(parsedArgs.error || parsedExpect.error), {
    what: 'The test of the script',
    name: script?.name,
  })
  const onArgs = (text) => {
    setArgsText(text)
    const parsed = parseJson(text, {})
    if (!parsed.error) setDraft((before) => ({ ...before, test: { ...before.test, args: parsed.value } }))
  }
  const onExpect = (text) => {
    setExpectText(text)
    const parsed = parseJson(text)
    if (parsed.error) return
    setDraft((before) => {
      const test = { args: before.test.args }
      if (text.trim() !== '') test.expect = parsed.value
      return { ...before, test }
    })
  }

  const problems = useMemo(() => {
    if (!draft) return []
    const found = draftProblems(draft)
    if (parsedArgs.error) found.push(`The arguments of the test: ${parsedArgs.error}`)
    if (parsedExpect.error) found.push(`What the test expects: ${parsedExpect.error}`)
    return found
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the texts decide the two errors
  }, [draft, argsText, expectText])

  const runTest = async () => {
    setTesting(true)
    try {
      setResult(await api.post(`${base}/test`, { draft }))
    } catch (failure) {
      setResult({ passed: false, error: failure.message, durationMs: 0 })
    } finally {
      setTesting(false)
    }
  }

  const saveVersion = async () => {
    setSaving(true)
    try {
      const found = await api.post(`${base}/versions`, { draft })
      adopt(found, { resetDraft: true })
      setResult(found.current?.testResult ?? null)
      showToast({ message: `Version ${found.version} saved: ${found.name} is in the library of nodes.` })
      loadCatalog({ reload: true }).catch(() => {})
    } catch (failure) {
      if (failure.status === 422 && failure.data?.test) setResult(failure.data.test)
      showToast({ message: failure.message })
    } finally {
      setSaving(false)
    }
  }

  const saveDescription = async () => {
    if (!script || description === (script.description ?? '')) return
    try {
      setScript(await api.put(base, { description }))
    } catch (failure) {
      showToast({ message: failure.message })
    }
  }

  const exportFile = async () => {
    try {
      const file = await api.get(`${base}/export`)
      saveBlob(new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' }), `${script.name}.script.json`)
    } catch (failure) {
      showToast({ message: failure.message })
    }
  }

  if (loadError) {
    return (
      <div className="flex h-full items-center justify-center p-6">
        <EmptyState
          illustration={<AsciiSkull preset="medium" eyes="x" tone="muted" />}
          title="This script cannot be opened"
          message={loadError}
          action={
            <Button icon={ArrowLeft} onClick={onBack}>
              All scripts
            </Button>
          }
        />
      </div>
    )
  }
  if (!script || !draft) {
    return (
      <p role="status" className="p-6 font-mono text-sm text-fg-muted">
        Loading the script…
      </p>
    )
  }

  const nextVersion = (script.version ?? 0) + 1
  const changed = !script.current || !sameDraft(draft, script.current)
  const blocked = problems.length > 0 || !sandbox

  return (
    <div className="flex min-h-full flex-col">
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            icon={ArrowLeft}
            aria-label="All scripts"
            title="All scripts"
            onClick={onBack}
          />
          <div className="min-w-0">
            <h2 className="truncate font-mono text-base font-semibold text-fg">{script.name}</h2>
            <p className="font-mono text-xs text-fg-muted">
              script · {script.version ? `version ${script.version}` : 'no version yet: not in the library'}
              {changed && script.version ? ' · draft changed' : ''}
              {SAVE_TEXT[saveState] ? (
                <span role="status" className={saveState === 'error' ? 'text-high-fg' : undefined}>
                  {' '}
                  · {SAVE_TEXT[saveState]}
                </span>
              ) : null}
            </p>
          </div>
          <Badge color="violet">Python 3.12</Badge>
          {script.builtin && <Badge color="cyan">shipped with Nik</Badge>}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="secondary" size="sm" icon={Download} onClick={exportFile}>
            Export
          </Button>
          {!script.builtin && (
            <Button variant="secondary" size="sm" icon={Trash2} onClick={() => setDeleteOpen(true)}>
              Delete
            </Button>
          )}
          <Button variant="secondary" size="sm" icon={FlaskConical} disabled={blocked || testing} onClick={runTest}>
            {testing ? 'Running…' : 'Run the test'}
          </Button>
          <Button size="sm" disabled={blocked || saving || !changed} onClick={saveVersion}>
            {saving ? 'Testing…' : `Save as version ${nextVersion}`}
          </Button>
        </div>
      </div>

      <div className="grid gap-4 p-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <div className="flex min-w-0 flex-col gap-4">
          <label className="flex flex-col gap-1 text-xs text-fg-muted" htmlFor="script-description">
            Description
            <input
              id="script-description"
              type="text"
              value={description}
              maxLength={300}
              placeholder="What it does, in a line"
              onChange={(event) => setDescription(event.target.value)}
              onBlur={saveDescription}
              className={`${INPUT} font-sans`}
            />
          </label>

          <section aria-label="Code" className="flex flex-col gap-2">
            <SectionTitle>Code</SectionTitle>
            <CodeEditor
              label="Code of the script"
              language="python"
              value={draft.code}
              onChange={(code) => change({ code })}
              minHeight="16rem"
            />
            <p className="text-xs text-fg-muted">
              <code className="font-mono">def main(args)</code> gets the arguments as a dictionary and returns something
              JSON can hold; what it prints is kept as the step’s log.
            </p>
          </section>

          {problems.length > 0 && (
            <ul
              role="alert"
              aria-label="Before the script can be tested"
              className="flex flex-col gap-1 border border-high-line bg-high-soft p-2 text-xs text-high-fg"
            >
              {problems.map((problem) => (
                <li key={problem}>{problem}</li>
              ))}
            </ul>
          )}

          <section aria-label="Test" className="flex flex-col gap-2">
            <SectionTitle>Test (kept with the script; it must pass for a version to be saved)</SectionTitle>
            <div className="grid gap-3 lg:grid-cols-2">
              <div className="flex min-w-0 flex-col gap-1">
                <span className="text-xs text-fg-muted">Arguments given to the test</span>
                <CodeEditor
                  label="Arguments of the test"
                  language="json"
                  value={argsText}
                  onChange={onArgs}
                  minHeight="6rem"
                  maxHeight="18rem"
                />
              </div>
              <div className="flex min-w-0 flex-col gap-1">
                <span className="text-xs text-fg-muted">
                  What it must return (empty: anything, as long as it does not fail)
                </span>
                <CodeEditor
                  label="What the test expects"
                  language="json"
                  value={expectText}
                  onChange={onExpect}
                  minHeight="6rem"
                  maxHeight="18rem"
                />
              </div>
            </div>
            <TestResult result={result} />
          </section>
        </div>

        <div className="flex min-w-0 flex-col gap-4">
          <Fields
            title="Arguments"
            fields={draft.arguments}
            withRequired
            onChange={(next) => change({ arguments: next })}
          />
          <Fields title="Outputs" fields={draft.outputs} onChange={(next) => change({ outputs: next })} />

          <section aria-label="Versions" className="flex flex-col gap-2">
            <SectionTitle>Versions</SectionTitle>
            {script.versions.length === 0 ? (
              <p className="text-xs text-fg-muted">
                None yet: the script becomes a node when its first version is saved.
              </p>
            ) : (
              <ul className="flex flex-col divide-y divide-line-soft border border-line">
                {script.versions.map((version) => (
                  <li key={version.version} className="flex items-center justify-between gap-2 px-2 py-1.5 text-xs">
                    <span>
                      <span className="font-mono text-fg">{version.version}</span>{' '}
                      {version.version === script.version && <Badge color="emerald">current</Badge>}
                      <span className="ml-2 text-fg-muted">
                        {formatDateTime(Date.parse(version.createdAt))} ·{' '}
                        <span className="font-mono">{version.createdBy}</span>
                      </span>
                    </span>
                    <Button
                      variant="ghost"
                      size="xs"
                      aria-label={`See version ${version.version}`}
                      onClick={() => setShownVersion(version.version)}
                    >
                      See
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section aria-label="Used by" className="flex flex-col gap-2">
            <SectionTitle>Used by</SectionTitle>
            {script.usedBy.length === 0 ? (
              <p className="text-xs text-fg-muted">No playbook uses this script.</p>
            ) : (
              <p className="text-xs text-fg">
                {script.usedBy.join(', ')}.{' '}
                <button
                  type="button"
                  onClick={onOpenPlaybooks}
                  className="text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  Open the playbooks
                </button>
              </p>
            )}
            <p className="text-xs text-fg-muted">
              A new version changes nothing for them: each node stays on its version until it is updated on the canvas.
            </p>
          </section>

          <SandboxBox available={sandbox} />
        </div>
      </div>

      <VersionDialog
        scriptId={id}
        number={shownVersion}
        draftCode={draft.code}
        onClose={() => setShownVersion(null)}
        onRestore={(version) => {
          const next = draftOf({ draft: version })
          setDraft(next)
          setArgsText(JSON.stringify(next.test.args, null, 2))
          setExpectText('expect' in next.test ? JSON.stringify(next.test.expect, null, 2) : '')
          setShownVersion(null)
          showToast({ message: `Version ${version.version} is in the draft: save it as a version to use it.` })
        }}
      />

      <Modal
        open={deleteOpen}
        onClose={() => setDeleteOpen(false)}
        title="Delete this script?"
        footer={
          <>
            <Button variant="secondary" onClick={() => setDeleteOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={async () => {
                try {
                  await api.del(base)
                  savedDraft.current = latestDraft.current // nothing left to save on the way out
                  setDeleteOpen(false)
                  showToast({ message: `${script.name} was deleted.` })
                  loadCatalog({ reload: true }).catch(() => {})
                  onBack()
                } catch (failure) {
                  setDeleteOpen(false)
                  showToast({ message: failure.message })
                }
              }}
            >
              Delete
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg">
          <span className="font-mono font-semibold">{script.name}</span> goes with all its versions. A script a playbook
          uses cannot be deleted.
        </p>
      </Modal>
    </div>
  )
}
