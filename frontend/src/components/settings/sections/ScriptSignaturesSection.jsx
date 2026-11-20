import { useCallback, useEffect, useState } from 'react'
import { Check, FileCode2, Pencil, Plus, Power, RotateCcw, Trash2, X } from 'lucide-react'
import { api } from '../../../services/api.js'
import { Badge, Button, Wait } from '../../ui/index.js'
import { useUnsavedChanges } from '../../../lib/unsaved.js'

/*
 * Rule sets → Script signatures (who manages rules).
 *
 * The signatures the Scripts tab of URL Analysis checks the scripts of a
 * scanned page against. Nik ships a set: each can be turned off, changed and
 * put back as it shipped, never deleted. Your own are added beside them.
 * A pattern is a regular expression, tried on long hostile texts before it
 * is saved so that it cannot stall a scan, and it can be tried here on a
 * piece of code. Changes apply to the scans made from then on.
 */

const INPUT =
  'w-full border border-line bg-panel px-3 py-2 text-sm text-fg placeholder:text-fg-muted ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const SEVERITY_COLORS = { high: 'red', medium: 'amber', low: 'slate' }
const BLANK = { key: '', title: '', severity: 'medium', points: 10, pattern: '', also: '', enabled: true }

const detailOf = (failure) => {
  const detail = failure?.data?.detail
  return typeof detail === 'object' && detail ? detail : { message: failure.message, field: '' }
}

export default function ScriptSignaturesSection() {
  const [rows, setRows] = useState(null)
  const [error, setError] = useState(null)
  const [message, setMessage] = useState(null)
  const [editing, setEditing] = useState(null) // null | 'new' | id
  const [form, setForm] = useState(BLANK)
  const [problem, setProblem] = useState(null) // { message, field }
  const [code, setCode] = useState('')
  const [tried, setTried] = useState(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(
    () =>
      api.get('/script-signatures').then(
        (found) => {
          setRows(found.signatures)
          setError(null)
        },
        (failure) => setError(failure.message),
      ),
    [],
  )
  useEffect(() => {
    load()
  }, [load])

  // The signature in the form as it was opened: what it is compared with before it is left.
  const openedRow = editing === null || editing === 'new' ? null : (rows ?? []).find((row) => row.id === editing)
  const opened = editing === 'new' ? BLANK : openedRow ? { ...BLANK, ...openedRow } : null
  const unsaved = useUnsavedChanges(
    editing !== null && opened !== null && JSON.stringify(form) !== JSON.stringify(opened),
    {
      what: editing === 'new' ? 'The new script signature' : 'The script signature',
      name: editing === 'new' ? '' : openedRow?.key,
      save: () => save(),
    },
  )
  /** Open a signature in the form (null: a new one), after asking about the one that is being written. */
  const edit = (row) =>
    unsaved.leave(() => {
      setEditing(row ? row.id : 'new')
      setForm(row ? { ...BLANK, ...row } : BLANK)
      setProblem(null)
      setTried(null)
      setMessage(null)
    })
  const set = (patch) => {
    setForm((old) => ({ ...old, ...patch }))
    setProblem(null)
    setTried(null)
  }
  const body = () => ({
    key: form.key,
    title: form.title,
    severity: form.severity,
    points: Number(form.points) || 0,
    pattern: form.pattern,
    also: form.also,
    enabled: form.enabled,
  })
  const check = async () => {
    setBusy(true)
    try {
      const answer = await api.post('/script-signatures/validate', { ...body(), code })
      setTried(answer)
      setProblem(answer.ok ? null : { message: answer.problem, field: answer.field })
    } catch (failure) {
      setProblem(detailOf(failure))
    } finally {
      setBusy(false)
    }
  }
  const save = async () => {
    setBusy(true)
    try {
      const saved =
        editing === 'new'
          ? await api.post('/script-signatures', body())
          : await api.put(`/script-signatures/${editing}`, body())
      setEditing(null)
      setMessage(`${saved.key} is saved. It applies to the scans made from now on.`)
      await load()
      return true
    } catch (failure) {
      setProblem(detailOf(failure))
      return false
    } finally {
      setBusy(false)
    }
  }
  const act = async (work, said) => {
    setError(null)
    try {
      await work()
      setMessage(said)
      await load()
    } catch (failure) {
      setError(detailOf(failure).message)
    }
  }
  const toggle = (row) =>
    act(
      () => api.put(`/script-signatures/${row.id}`, { ...row, enabled: !row.enabled }),
      `${row.key} is ${row.enabled ? 'off' : 'on'}.`,
    )
  const restore = (row) =>
    act(() => api.post(`/script-signatures/${row.id}/restore`), `${row.key} is as Nik ships it again.`)
  const remove = (row) => act(() => api.del(`/script-signatures/${row.id}`), `${row.key} is deleted.`)

  const current = editing && editing !== 'new' ? rows?.find((row) => row.id === editing) : null

  return (
    <section className="space-y-5">
      <div>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <FileCode2 className="h-5 w-5 text-accent" aria-hidden="true" />
            <h2 className="text-base font-semibold text-fg">Script signatures</h2>
            {rows && <Badge color="slate">{rows.length}</Badge>}
          </div>
          <Button size="sm" icon={Plus} onClick={() => edit(null)} disabled={editing === 'new'}>
            Add a signature
          </Button>
        </div>
        <p className="mt-1 text-sm text-fg-muted">
          What the scripts of a scanned page are checked against in <em>URL Analysis → Scripts</em>. A signature is a
          regular expression (case does not matter), with a severity and the points it adds to the score of the scan.
          Changes apply to the scans made from now on: <em>Analyse again</em> on an address reads it with the signatures
          as they are now.
        </p>
      </div>

      <p
        role="status"
        className={message ? 'border border-accent-strong bg-accent-soft px-3 py-2 text-sm text-accent-fg' : 'sr-only'}
      >
        {message}
      </p>
      {error && (
        <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
          {error}
        </p>
      )}

      {editing && (
        <form
          aria-label={editing === 'new' ? 'A new signature' : `Signature ${form.key}`}
          onSubmit={(event) => {
            event.preventDefault()
            save()
          }}
          className="space-y-3 border border-line p-4"
        >
          <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-fg-muted">Key</span>
              <input
                type="text"
                value={form.key}
                disabled={editing !== 'new'}
                maxLength={61}
                placeholder="team.gate"
                onChange={(event) => set({ key: event.target.value })}
                aria-invalid={problem?.field === 'key'}
                className={`${INPUT} font-mono disabled:opacity-60`}
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-fg-muted">Title</span>
              <input
                type="text"
                value={form.title}
                maxLength={200}
                placeholder="What it says of a script that matches"
                onChange={(event) => set({ title: event.target.value })}
                aria-invalid={problem?.field === 'title'}
                className={INPUT}
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-fg-muted">Severity</span>
              <select
                value={form.severity}
                onChange={(event) => set({ severity: event.target.value })}
                className={INPUT}
              >
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
              </select>
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-fg-muted">
                Points (0 to 100, added to the score)
              </span>
              <input
                type="number"
                min="0"
                max="100"
                value={form.points}
                onChange={(event) => set({ points: event.target.value })}
                className={INPUT}
              />
            </label>
          </div>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-fg-muted">Pattern</span>
            <textarea
              rows={3}
              value={form.pattern}
              spellCheck={false}
              maxLength={2000}
              onChange={(event) => set({ pattern: event.target.value })}
              aria-invalid={problem?.field === 'pattern'}
              className={`${INPUT} font-mono text-xs`}
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-fg-muted">
              And, somewhere in the same script (optional): a key listener is a keylogger only if the script also sends
              something out
            </span>
            <textarea
              rows={2}
              value={form.also}
              spellCheck={false}
              maxLength={2000}
              onChange={(event) => set({ also: event.target.value })}
              aria-invalid={problem?.field === 'also'}
              className={`${INPUT} font-mono text-xs`}
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-fg-muted">Try it on this code</span>
            <textarea
              rows={4}
              value={code}
              spellCheck={false}
              placeholder="Paste a script, or a part of one"
              onChange={(event) => {
                setCode(event.target.value)
                setTried(null)
              }}
              className={`${INPUT} font-mono text-xs`}
            />
          </label>
          {problem && (
            <p role="alert" className="text-sm text-high">
              {problem.message}
            </p>
          )}
          {tried?.ok && (
            <p role="status" className="text-sm text-fg">
              {tried.matches === undefined
                ? 'The signature can be saved.'
                : tried.timedOut
                  ? 'It took too long on this code and would be left out of such a script.'
                  : tried.matches
                    ? `It matches, on line ${tried.finding.line}: ${tried.finding.excerpt}`
                    : 'It does not match this code.'}
            </p>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <Button type="submit" icon={Check} disabled={busy}>
              Save
            </Button>
            <Button variant="secondary" onClick={check} disabled={busy}>
              {code ? 'Check and try' : 'Check'}
            </Button>
            <Button variant="ghost" icon={X} onClick={() => unsaved.leave(() => setEditing(null))}>
              Cancel
            </Button>
            {current?.builtin && (
              <span className="text-xs text-fg-muted">
                One of Nik's own: it keeps its key, and <em>Restore</em> puts it back as it ships.
              </span>
            )}
          </div>
        </form>
      )}

      <div className="overflow-x-auto border border-line">
        <table className="w-full min-w-[720px] text-left text-sm">
          <caption className="sr-only">Script signatures</caption>
          <thead>
            <tr className="border-b border-line text-xs uppercase tracking-wider text-fg-muted">
              <th scope="col" className="px-3 py-2 font-semibold">
                Signature
              </th>
              <th scope="col" className="px-3 py-2 font-semibold">
                Severity
              </th>
              <th scope="col" className="px-3 py-2 text-right font-semibold">
                Points
              </th>
              <th scope="col" className="px-3 py-2 font-semibold">
                State
              </th>
              <th scope="col" className="px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {(rows ?? []).map((row) => (
              <tr key={row.id} className="border-b border-line-soft last:border-0">
                <td className="px-3 py-2">
                  <span className={`block ${row.enabled ? 'text-fg' : 'text-fg-muted line-through'}`}>{row.title}</span>
                  <span className="font-mono text-xs text-fg-muted">{row.key}</span>
                </td>
                <td className="px-3 py-2">
                  <Badge color={SEVERITY_COLORS[row.severity] ?? 'slate'}>{row.severity}</Badge>
                </td>
                <td className="px-3 py-2 text-right tabular-nums text-fg">{row.points}</td>
                <td className="px-3 py-2 text-xs text-fg-muted">
                  {row.enabled ? 'on' : 'off'}
                  {' · '}
                  {row.builtin ? (row.changed ? `Nik's, changed by ${row.updatedBy}` : "Nik's") : `by ${row.updatedBy}`}
                </td>
                <td className="whitespace-nowrap px-3 py-2 text-right">
                  <Button
                    size="xs"
                    variant="ghost"
                    icon={Power}
                    onClick={() => toggle(row)}
                    aria-label={`Turn ${row.key} ${row.enabled ? 'off' : 'on'}`}
                    title={row.enabled ? 'Turn off' : 'Turn on'}
                  />
                  <Button
                    size="xs"
                    variant="ghost"
                    icon={Pencil}
                    onClick={() => edit(row)}
                    aria-label={`Edit ${row.key}`}
                    title="Edit"
                  />
                  {row.builtin ? (
                    row.changed && (
                      <Button
                        size="xs"
                        variant="ghost"
                        icon={RotateCcw}
                        onClick={() => restore(row)}
                        aria-label={`Restore ${row.key}`}
                        title="Put back as Nik ships it"
                      />
                    )
                  ) : (
                    <Button
                      size="xs"
                      variant="ghost"
                      icon={Trash2}
                      onClick={() => remove(row)}
                      aria-label={`Delete ${row.key}`}
                      title="Delete"
                    />
                  )}
                </td>
              </tr>
            ))}
            {rows === null && !error && (
              <tr>
                <td colSpan={5} className="px-3 py-6">
                  <Wait>Loading the signatures…</Wait>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  )
}
