import { useCallback, useEffect, useState } from 'react'
import { ArrowDown, ArrowUp, Pencil, Plus, Trash2 } from 'lucide-react'
import { api } from '../../../services/api.js'
import {
  OPERATORS,
  RULE_ACTIONS,
  conditionText,
  isUnary,
  moved,
  parseSample,
  ruleBody,
  ruleForm,
  ruleProblem,
  ruleText,
} from '../../../domain/mappers.js'
import { instancePath } from '../../../domain/settingsNav.js'
import { setPath } from '../../../lib/location.js'
import { Badge, Button, Modal } from '../../ui/index.js'

/*
 * Incidents → Pre-processing rules (who configures incidents).
 *
 * What is done with an item a connection fetched before it becomes an
 * incident: dropped, linked to the open incident it belongs to, made and
 * closed as a duplicate, or left to a script to say. The rules are tried in
 * their order and the first that decides wins; with none, the item becomes
 * an incident. "Try" says which rule would decide for a sample.
 */

const INPUT =
  'w-full border border-line bg-canvas px-2 py-1.5 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-60'
const LABEL = 'text-xs font-medium text-fg-muted'

function RuleDialog({ rule, same, onClose, onSaved }) {
  const [form, setForm] = useState(() => ruleForm(rule))
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const problem = ruleProblem(form)
  const finds = form.action === 'link_to_existing' || form.action === 'close_duplicate'
  const condition = form.condition

  const save = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const body = ruleBody(form)
      onSaved(
        form.id
          ? await api.put(`/preprocess-rules/${encodeURIComponent(form.id)}`, body)
          : await api.post('/preprocess-rules', body),
      )
    } catch (failure) {
      setError(failure.message)
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={form.id ? `Rule: ${rule.name}` : 'New rule'}
      maxWidth="max-w-2xl"
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button type="submit" form="preprocess-rule" size="sm" disabled={busy || Boolean(problem)}>
            Save the rule
          </Button>
        </>
      }
    >
      <form id="preprocess-rule" onSubmit={save} className="flex flex-col gap-3">
        <div className="flex flex-col gap-1">
          <label htmlFor="rule-name" className={LABEL}>
            Name
          </label>
          <input
            id="rule-name"
            type="text"
            value={form.name}
            maxLength={120}
            autoFocus
            autoComplete="off"
            onChange={(event) => setForm({ ...form, name: event.target.value })}
            className={INPUT}
          />
        </div>
        <fieldset className="flex flex-col gap-1">
          <legend className={LABEL}>When (nothing for always)</legend>
          {condition.kept ? (
            <p className="font-mono text-xs text-fg-muted">{conditionText(condition.kept)}</p>
          ) : (
            <div className="grid grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1fr)] gap-2">
              <input
                type="text"
                aria-label="What to compare"
                value={condition.left}
                spellCheck={false}
                placeholder="{{ incident.severity }} or {{ item.type }}"
                onChange={(event) => setForm({ ...form, condition: { ...condition, left: event.target.value } })}
                className={`${INPUT} font-mono text-xs`}
              />
              <select
                aria-label="How it compares"
                value={condition.op}
                onChange={(event) => setForm({ ...form, condition: { ...condition, op: event.target.value } })}
                className={`${INPUT} cursor-pointer`}
              >
                {OPERATORS.map((operator) => (
                  <option key={operator.id} value={operator.id}>
                    {operator.label}
                  </option>
                ))}
              </select>
              {!isUnary(condition.op) && (
                <input
                  type="text"
                  aria-label="With what"
                  value={condition.right}
                  spellCheck={false}
                  onChange={(event) => setForm({ ...form, condition: { ...condition, right: event.target.value } })}
                  className={`${INPUT} font-mono text-xs`}
                />
              )}
            </div>
          )}
          <span className="text-xs text-fg-subtle">
            <code className="font-mono">incident</code> is what the item would become (its type and the fields its
            mapper gave), <code className="font-mono">item</code> is what came.
          </span>
        </fieldset>
        <div className="flex flex-col gap-1">
          <label htmlFor="rule-action" className={LABEL}>
            Then
          </label>
          <select
            id="rule-action"
            value={form.action}
            onChange={(event) => setForm({ ...form, action: event.target.value })}
            className={`${INPUT} cursor-pointer`}
          >
            {RULE_ACTIONS.map((action) => (
              <option key={action.id} value={action.id}>
                {action.label}
              </option>
            ))}
          </select>
          <span className="text-xs text-fg-subtle">
            {RULE_ACTIONS.find((action) => action.id === form.action)?.hint}
          </span>
        </div>
        {finds && (
          <>
            <fieldset className="flex flex-col gap-1">
              <legend className={LABEL}>The same incident is an open one with the same</legend>
              <div className="flex flex-wrap gap-x-4 gap-y-1">
                {same.map((name) => (
                  <label key={name} className="flex items-center gap-1.5 text-sm text-fg">
                    <input
                      type="checkbox"
                      checked={form.same.includes(name)}
                      onChange={(event) =>
                        setForm({
                          ...form,
                          same: event.target.checked ? [...form.same, name] : form.same.filter((item) => item !== name),
                        })
                      }
                      className="h-4 w-4 accent-accent"
                    />
                    {name}
                  </label>
                ))}
              </div>
            </fieldset>
            <div className="flex max-w-xs flex-col gap-1">
              <label htmlFor="rule-within" className={LABEL}>
                Made in the last hours (empty for any time)
              </label>
              <input
                id="rule-within"
                type="text"
                inputMode="numeric"
                value={form.withinHours}
                onChange={(event) => setForm({ ...form, withinHours: event.target.value })}
                className={`${INPUT} font-mono`}
              />
            </div>
          </>
        )}
        {form.action === 'run_script' && (
          <div className="flex flex-col gap-1">
            <label htmlFor="rule-script" className={LABEL}>
              The script (its name in the library)
            </label>
            <input
              id="rule-script"
              type="text"
              value={form.script}
              spellCheck={false}
              onChange={(event) => setForm({ ...form, script: event.target.value })}
              className={`${INPUT} font-mono`}
            />
            <span className="text-xs text-fg-subtle">
              It is given <code className="font-mono">item</code> and <code className="font-mono">incident</code> and
              returns <code className="font-mono">{'{"action": "drop"}'}</code>,{' '}
              <code className="font-mono">{'{"action": "link_to_existing", "same": ["host"]}'}</code>, or anything else
              to go on.
            </span>
          </div>
        )}
        <label className="flex items-center gap-2 text-sm text-fg">
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={(event) => setForm({ ...form, enabled: event.target.checked })}
            className="h-4 w-4 accent-accent"
          />
          The rule is on
        </label>
        {(error || problem) && (
          <p role={error ? 'alert' : 'status'} className={`text-sm ${error ? 'text-high-fg' : 'text-fg-muted'}`}>
            {error || problem}
          </p>
        )}
      </form>
    </Modal>
  )
}

export default function PreprocessSection() {
  const [found, setFound] = useState(null)
  const [connections, setConnections] = useState([])
  const [error, setError] = useState(null)
  const [editing, setEditing] = useState(undefined) // undefined: closed; null: a new rule; a rule
  const [instanceId, setConnectionId] = useState('')
  const [pasted, setPasted] = useState('')
  const [tried, setTried] = useState(null)

  const load = useCallback(async () => {
    try {
      setFound(await api.get('/preprocess-rules'))
      setError(null)
    } catch (failure) {
      setError(failure.message)
    }
  }, [])
  useEffect(() => {
    load()
    api
      .get('/fetch')
      .then((status) => {
        setConnections(status.instances)
        setConnectionId((current) => current || status.instances[0]?.instanceId || '')
      })
      .catch(() => setConnections([]))
  }, [load])

  const rules = found?.rules ?? []
  const act = async (request) => {
    setError(null)
    try {
      const next = await request()
      if (next?.rules) setFound({ ...found, ...next })
      else await load()
    } catch (failure) {
      setError(failure.message)
    }
  }
  const move = (rule, by) =>
    act(() =>
      api.put('/preprocess-rules/order', {
        ids: moved(
          rules.map((item) => item.id),
          rule.id,
          by,
        ),
      }),
    )
  const sample = parseSample(pasted)
  const tryIt = async () => {
    setError(null)
    try {
      setTried(await api.post('/preprocess-rules/try', { instanceId, item: sample.item }))
    } catch (failure) {
      setTried(null)
      setError(failure.message)
    }
  }

  return (
    <div className="flex max-w-4xl flex-col gap-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <p className="max-w-2xl text-sm text-fg-muted">
          What is done with an item a connection fetched before it becomes an incident. The rules are tried in this
          order; the first that decides wins, and with none the item becomes an incident.
        </p>
        <Button size="sm" icon={Plus} onClick={() => setEditing(null)}>
          New rule
        </Button>
      </div>
      {error && (
        <p role="alert" className="text-sm text-high-fg">
          {error}
        </p>
      )}
      {found === null && !error ? (
        <p role="status" className="font-mono text-sm text-fg-muted">
          Loading the rules…
        </p>
      ) : rules.length === 0 ? (
        <p className="text-sm text-fg-muted">No rule yet: every new item becomes an incident.</p>
      ) : (
        <ol aria-label="Pre-processing rules" className="flex flex-col divide-y divide-line-soft border border-line">
          {rules.map((rule, index) => (
            <li key={rule.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2">
              <span className="w-5 font-mono text-xs text-fg-subtle">{index + 1}</span>
              <span className="min-w-0 flex-1">
                <span className="block text-sm font-medium text-fg">
                  {rule.name} {!rule.enabled && <Badge color="slate">off</Badge>}
                </span>
                <span className="block text-xs text-fg-muted">
                  {rule.when?.all || rule.when?.any ? `when ${conditionText(rule.when)}: ` : 'always: '}
                  {ruleText(rule)}
                </span>
              </span>
              <span className="flex shrink-0">
                <Button
                  variant="ghost"
                  size="xs"
                  icon={ArrowUp}
                  aria-label={`Move ${rule.name} up`}
                  disabled={index === 0}
                  onClick={() => move(rule, -1)}
                />
                <Button
                  variant="ghost"
                  size="xs"
                  icon={ArrowDown}
                  aria-label={`Move ${rule.name} down`}
                  disabled={index === rules.length - 1}
                  onClick={() => move(rule, 1)}
                />
                <Button
                  variant="ghost"
                  size="xs"
                  icon={Pencil}
                  aria-label={`Edit ${rule.name}`}
                  onClick={() => setEditing(rule)}
                />
                <Button
                  variant="ghost"
                  size="xs"
                  icon={Trash2}
                  aria-label={`Delete ${rule.name}`}
                  onClick={() => act(() => api.del(`/preprocess-rules/${encodeURIComponent(rule.id)}`))}
                />
              </span>
            </li>
          ))}
        </ol>
      )}

      <section aria-label="Try on a sample" className="flex flex-col gap-2 border border-line p-3">
        <h3 className="text-sm font-semibold text-fg">Try on a sample</h3>
        {connections.length === 0 ? (
          <p className="text-sm text-fg-muted">
            No connection can fetch yet: a sample is tried as an item of a connection, with its classifier and its
            mapper.
          </p>
        ) : (
          <>
            <label className="flex max-w-sm flex-col gap-1">
              <span className={LABEL}>As an item fetched by</span>
              <select
                aria-label="The instance the sample comes from"
                value={instanceId}
                onChange={(event) => setConnectionId(event.target.value)}
                className={`${INPUT} cursor-pointer`}
              >
                {connections.map((connection) => (
                  <option key={connection.instanceId} value={connection.instanceId}>
                    {connection.connection}
                  </option>
                ))}
              </select>
            </label>
            <textarea
              aria-label="A sample item, as JSON"
              value={pasted}
              rows={4}
              spellCheck={false}
              placeholder='{"id": "T-77", "title": "Port scan"}'
              onChange={(event) => setPasted(event.target.value)}
              className={`${INPUT} font-mono text-xs`}
            />
            {sample.problem && <p className="text-xs text-high-fg">{sample.problem}</p>}
            <div className="flex flex-wrap items-center gap-3">
              <Button variant="secondary" size="sm" disabled={!sample.item || !instanceId} onClick={tryIt}>
                Try
              </Button>
              {/* The type and the fields the sample gets are those of the instance: they are set in its form. */}
              {instanceId && (
                <Button variant="ghost" size="sm" onClick={() => setPath(instancePath(instanceId, 'classifier'))}>
                  Its classifier and its mappers
                </Button>
              )}
              {tried && (
                <span role="status" className="text-sm text-fg">
                  {tried.decision.rule ? (
                    <>
                      The rule <strong>{tried.decision.rule}</strong> decides:{' '}
                      {tried.decision.action.replaceAll('_', ' ')}
                      {tried.decision.incident ? ` (${tried.decision.incident.name})` : ''}.
                    </>
                  ) : (
                    <>
                      No rule decides: it becomes the incident <strong>{tried.incident.name ?? '(no name)'}</strong>.
                    </>
                  )}
                </span>
              )}
            </div>
          </>
        )}
      </section>

      {editing !== undefined && (
        <RuleDialog
          rule={editing}
          same={found?.same ?? []}
          onClose={() => setEditing(undefined)}
          onSaved={() => {
            setEditing(undefined)
            load()
          }}
        />
      )}
    </div>
  )
}
