import { useMemo, useState } from 'react'
import { Plus, Trash2, X } from 'lucide-react'
import { Button } from '../ui/index.js'
import {
  asksApproval,
  entryOf,
  eventLabel,
  headingOf,
  objectName,
  runsOn,
  sampleFilter,
  valueTree,
} from '../../domain/automation/catalog.js'
import {
  OPERATORS,
  UNARY,
  connect,
  disconnect,
  edgesFrom,
  nodeOf,
  portName,
  portsOf,
  pruneEdges,
  renameNode,
  unreadable,
  updateNode,
} from '../../domain/automation/graph.js'
import { ROLES } from '../../domain/permissions.js'
import { useFields } from '../../context/FieldsContext.jsx'
import ExpressionInput from './ExpressionInput.jsx'
import {
  DurationInput,
  Field,
  INPUT,
  NumberInput,
  SectionTitle,
  Seg,
  SelectInput,
  Switch,
  TextInput,
} from './fields.jsx'

/*
 * ============================================================================
 * INSPECTOR — the settings of the selected node
 * ============================================================================
 *
 * A form built from what the node is: the arguments its action or script
 * declares, the comparisons of a condition, the question of an approval.
 * Every text takes {{ expressions }} (ExpressionInput). Below the settings:
 * where the node goes next (edges can be drawn here, without a pointer),
 * what it gives to the nodes after it, and what is still to fix.
 *
 * With no node selected it shows the playbook itself: what it takes when it
 * is run by hand or by another playbook, and what it gives back.
 */

const TYPES = ['text', 'number', 'bool', 'list', 'object', 'any'].map((type) => ({ value: type, label: type }))

/** A list, an object or free text: JSON when it reads as JSON, a text (with expressions) otherwise. */
function JsonInput({ id, value, onChange, tree, disabled, label }) {
  const [draft, setDraft] = useState(null)
  const shown =
    draft ??
    (typeof value === 'string' ? value : value === undefined || value === null ? '' : JSON.stringify(value, null, 2))
  return (
    <div onBlur={() => setDraft(null)}>
      <ExpressionInput
        id={id}
        label={label}
        multiline
        tree={tree}
        disabled={disabled}
        value={shown}
        placeholder='a value, {{ an.expression }} or JSON: ["a", "b"]'
        onChange={(text) => {
          setDraft(text)
          const trimmed = text.trim()
          if (/^[[{]/.test(trimmed)) {
            try {
              onChange(JSON.parse(trimmed))
              return
            } catch {
              /* not JSON yet: kept as text */
            }
          }
          onChange(text)
        }}
      />
    </div>
  )
}

/** What "is one of" compares with: values separated by commas (a list), or an expression that gives one. */
function ListInput({ value, onChange, tree, disabled, label }) {
  const [draft, setDraft] = useState(null)
  const shown = draft ?? (Array.isArray(value) ? value.join(', ') : typeof value === 'string' ? value : '')
  return (
    <div onBlur={() => setDraft(null)}>
      <ExpressionInput
        label={label}
        tree={tree}
        disabled={disabled}
        value={shown}
        placeholder="high, critical"
        onChange={(text) => {
          setDraft(text)
          onChange(
            text.includes('{{')
              ? text
              : text
                  .split(',')
                  .map((part) => part.trim())
                  .filter(Boolean),
          )
        }}
      />
    </div>
  )
}

/** One argument of an action or a script, by its type. */
function ArgumentField({ argument, value, onChange, tree, disabled, problem }) {
  const label = argument.name
  const hint = argument.description || null
  const isExpression = typeof value === 'string' && value.includes('{{')
  return (
    <Field label={label} hint={hint} required={Boolean(argument.required)} problem={problem}>
      {(id) => {
        if (argument.type === 'choice' && !isExpression) {
          const choices = argument.choices ?? []
          return (
            <SelectInput
              id={id}
              value={value ?? ''}
              disabled={disabled}
              onChange={onChange}
              options={[
                ...(choices.includes('') ? [] : [{ value: '', label: '(not set)' }]),
                ...choices.map((choice) => ({ value: choice, label: choice === '' ? '(none)' : choice })),
              ]}
            />
          )
        }
        if (argument.type === 'bool' && !isExpression) {
          return (
            <SelectInput
              id={id}
              value={value === true ? 'true' : value === false ? 'false' : ''}
              disabled={disabled}
              onChange={(next) => onChange(next === '' ? undefined : next === 'true')}
              options={[
                {
                  value: '',
                  label: `(default${argument.default === undefined ? '' : `: ${argument.default ? 'yes' : 'no'}`})`,
                },
                { value: 'true', label: 'yes' },
                { value: 'false', label: 'no' },
              ]}
            />
          )
        }
        if (argument.type === 'number') {
          return (
            <ExpressionInput
              id={id}
              tree={tree}
              disabled={disabled}
              value={value ?? ''}
              placeholder={argument.default === undefined ? '' : String(argument.default)}
              onChange={(text) => {
                const trimmed = text.trim()
                onChange(trimmed !== '' && /^-?\d+(\.\d+)?$/.test(trimmed) ? Number(trimmed) : text)
              }}
            />
          )
        }
        if (['list', 'object', 'any'].includes(argument.type)) {
          return <JsonInput id={id} value={value} onChange={onChange} tree={tree} disabled={disabled} />
        }
        return (
          <ExpressionInput
            id={id}
            tree={tree}
            disabled={disabled}
            multiline={['text', 'body', 'description', 'html'].includes(argument.name)}
            value={value ?? ''}
            onChange={onChange}
          />
        )
      }}
    </Field>
  )
}

/** "All of" / "any of" a list of comparisons: a condition node, a trigger's filter, a wait's "until". */
function Conditions({ value, onChange, tree, disabled, label }) {
  const key = value?.any ? 'any' : 'all'
  const items = Array.isArray(value?.[key]) ? value[key] : []
  const write = (nextKey, nextItems) => onChange({ [nextKey]: nextItems })
  const change = (index, patch) =>
    write(
      key,
      items.map((item, at) => (at === index ? { ...item, ...patch } : item)),
    )
  return (
    <div className="flex flex-col gap-2">
      <Seg
        label={`${label}: how the comparisons combine`}
        value={key}
        disabled={disabled}
        onChange={(next) => write(next, items)}
        options={[
          { value: 'all', label: 'All of' },
          { value: 'any', label: 'Any of' },
        ]}
      />
      {items.map((item, index) => (
        <div
          key={index}
          role="group"
          aria-label={`Comparison ${index + 1}`}
          className="flex flex-col gap-1 border border-line-soft p-2"
        >
          <ExpressionInput
            label={`Comparison ${index + 1}: what to compare`}
            tree={tree}
            disabled={disabled}
            value={item.left ?? ''}
            placeholder="{{ trigger.incident.severity }}"
            onChange={(left) => change(index, { left })}
          />
          <div className="flex gap-1">
            <SelectInput
              aria-label={`Comparison ${index + 1}: operator`}
              value={item.op ?? 'eq'}
              disabled={disabled}
              onChange={(op) => change(index, { op })}
              options={OPERATORS.map((operator) => ({ value: operator.id, label: operator.label }))}
            />
            {!disabled && (
              <Button
                variant="ghost"
                size="xs"
                icon={X}
                aria-label={`Remove comparison ${index + 1}`}
                title="Remove this comparison"
                onClick={() =>
                  write(
                    key,
                    items.filter((_, at) => at !== index),
                  )
                }
              />
            )}
          </div>
          {item.op === 'in' ? (
            <ListInput
              label={`Comparison ${index + 1}: with what`}
              tree={tree}
              disabled={disabled}
              value={item.right}
              onChange={(right) => change(index, { right })}
            />
          ) : UNARY.has(item.op) ? null : (
            <ExpressionInput
              label={`Comparison ${index + 1}: with what`}
              tree={tree}
              disabled={disabled}
              value={
                typeof item.right === 'string' ? item.right : item.right === undefined ? '' : JSON.stringify(item.right)
              }
              placeholder={item.op === 'matches' ? 'a pattern (regular expression)' : 'a value'}
              onChange={(right) => change(index, { right })}
            />
          )}
        </div>
      ))}
      {!disabled && (
        <Button
          variant="secondary"
          size="xs"
          icon={Plus}
          className="self-start"
          onClick={() => write(key, [...items, { left: '', op: 'eq', right: '' }])}
        >
          Add a comparison
        </Button>
      )}
    </div>
  )
}

/** "If it fails": stop at once, or try again some times before the "on error" line. */
function OnError({ config, onConfig, disabled }) {
  const mode = config.on_error?.mode === 'retry' ? 'retry' : 'stop'
  return (
    <div className="flex flex-col gap-2">
      <SectionTitle>If it fails</SectionTitle>
      <div className="flex flex-wrap items-center gap-2">
        <Seg
          label="If it fails"
          value={mode}
          disabled={disabled}
          onChange={(next) =>
            onConfig({
              on_error: next === 'retry' ? { mode: 'retry', times: config.on_error?.times ?? 3 } : { mode: 'stop' },
            })
          }
          options={[
            { value: 'stop', label: 'Stop at once' },
            { value: 'retry', label: 'Try again' },
          ]}
        />
        {mode === 'retry' && (
          <>
            <NumberInput
              aria-label="How many times to try again"
              value={config.on_error?.times ?? 3}
              min={1}
              max={100}
              disabled={disabled}
              className="w-16!"
              onChange={(times) => onConfig({ on_error: { mode: 'retry', times: times ?? 1 } })}
            />
            <span className="text-xs text-fg-muted">times (100 at most)</span>
          </>
        )}
      </div>
      <p className="text-xs text-fg-muted">
        Then the “on error” line, if one is drawn from this node; the run fails otherwise.
      </p>
    </div>
  )
}

/** How long an approval waits, and what happens when nobody answers. */
function ApprovalWait({ waitSeconds, onExpire, onChange, disabled, choices }) {
  return (
    <>
      <Field label="Waits" hint={waitSeconds ? null : 'Without limit: the run waits until someone answers.'}>
        {(id) => (
          <div className="flex flex-wrap items-center gap-2">
            <Seg
              label="How long it waits"
              value={waitSeconds ? 'limit' : 'forever'}
              disabled={disabled}
              onChange={(next) => onChange({ wait_seconds: next === 'limit' ? 3600 : undefined })}
              options={[
                { value: 'forever', label: 'Without limit' },
                { value: 'limit', label: 'For' },
              ]}
            />
            {waitSeconds ? (
              <DurationInput
                id={id}
                value={waitSeconds}
                disabled={disabled}
                onChange={(seconds) => onChange({ wait_seconds: seconds ?? 60 })}
              />
            ) : null}
          </div>
        )}
      </Field>
      {waitSeconds ? (
        <Field label="When the wait ends">
          {(id) => (
            <SelectInput
              id={id}
              value={onExpire ?? 'skip'}
              disabled={disabled}
              onChange={(next) => onChange({ on_expire: next })}
              options={choices}
            />
          )}
        </Field>
      ) : null}
    </>
  )
}

const EXPIRE_NODE = [
  { value: 'skip', label: 'go on as refused' },
  { value: 'refuse', label: 'refuse' },
  { value: 'stop', label: 'stop the run' },
]
const EXPIRE_INLINE = [
  { value: 'skip', label: 'skip the node and go on' },
  { value: 'stop', label: 'stop the run' },
]

/** Free name → value pairs: the inputs given to another playbook. */
function Pairs({ value, onChange, tree, disabled }) {
  const entries = Object.entries(value && typeof value === 'object' ? value : {})
  const write = (next) => onChange(Object.fromEntries(next))
  return (
    <div className="flex flex-col gap-2">
      {entries.map(([name, item], index) => (
        <div key={index} className="flex flex-col gap-1 border border-line-soft p-2">
          <div className="flex gap-1">
            <TextInput
              aria-label={`Input ${index + 1}: name`}
              value={name}
              disabled={disabled}
              placeholder="name"
              onChange={(next) => write(entries.map((pair, at) => (at === index ? [next, pair[1]] : pair)))}
            />
            {!disabled && (
              <Button
                variant="ghost"
                size="xs"
                icon={X}
                aria-label={`Remove input ${index + 1}`}
                onClick={() => write(entries.filter((_, at) => at !== index))}
              />
            )}
          </div>
          <ExpressionInput
            label={`Input ${index + 1}: value`}
            tree={tree}
            disabled={disabled}
            value={typeof item === 'string' ? item : JSON.stringify(item)}
            onChange={(next) => write(entries.map((pair, at) => (at === index ? [pair[0], next] : pair)))}
          />
        </div>
      ))}
      {!disabled && (
        <Button
          variant="secondary"
          size="xs"
          icon={Plus}
          className="self-start"
          onClick={() => write([...entries, [`input_${entries.length + 1}`, '']])}
        >
          Add an input
        </Button>
      )}
    </div>
  )
}

const ROLE_OPTIONS = ROLES.filter((role) => role.shown).map((role) => ({ value: role.id, label: role.label }))
const INPUT_TYPES = [
  { value: 'text', label: 'text' },
  { value: 'number', label: 'number' },
  { value: 'bool', label: 'yes / no' },
]

/** Who a task or a question is for: the owner of the incident, a user, a role, or anyone (a question). */
function Assignee({ value, onChange, tree, disabled, anyone }) {
  const who = value ?? {}
  const mode = who.user !== undefined ? 'user' : who.role ? 'role' : who.owner ? 'owner' : anyone ? 'anyone' : 'owner'
  return (
    <Field label="For" hint={mode === 'owner' ? 'Whoever has the incident when it is done.' : null}>
      {(id) => (
        <div className="flex flex-col gap-1.5">
          <Seg
            label="Who it is for"
            value={mode}
            disabled={disabled}
            onChange={(next) =>
              onChange(
                next === 'user'
                  ? { user: '' }
                  : next === 'role'
                    ? { role: 'analyst' }
                    : next === 'owner'
                      ? { owner: true }
                      : undefined,
              )
            }
            options={[
              ...(anyone ? [{ value: 'anyone', label: 'Anyone' }] : []),
              { value: 'owner', label: 'The owner' },
              { value: 'user', label: 'A user' },
              { value: 'role', label: 'A role' },
            ]}
          />
          {mode === 'user' && (
            <ExpressionInput
              id={id}
              label="The user it is for"
              tree={tree}
              disabled={disabled}
              value={who.user ?? ''}
              placeholder="anna, or {{ incident.owner }}"
              onChange={(user) => onChange({ user })}
            />
          )}
          {mode === 'role' && (
            <SelectInput
              id={id}
              aria-label="The role it is for"
              value={who.role}
              disabled={disabled}
              options={ROLE_OPTIONS}
              onChange={(role) => onChange({ role })}
            />
          )}
        </div>
      )}
    </Field>
  )
}

/** The fields of the incident a person fills when they complete a task or answer a question. */
function FieldsToFill({ value, onChange, disabled, problem }) {
  const { fields } = useFields()
  const chosen = Array.isArray(value) ? value : []
  const fillable = fields.filter((field) => field.appliesTo === 'incident' && field.writable !== false)
  const left = fillable.filter((field) => !chosen.includes(field.name))
  const labelOf = (name) => fillable.find((field) => field.name === name)?.label || name
  return (
    <Field label="Fields to fill" hint="Written to the incident when it is done." problem={problem}>
      {(id) => (
        <div className="flex flex-col gap-1">
          {chosen.map((name) => (
            <div key={name} className="flex items-center justify-between gap-1 border border-line-soft pl-2 text-xs">
              <span className="min-w-0 truncate py-1">
                {labelOf(name)} <span className="font-mono text-[11px] text-fg-subtle">{name}</span>
              </span>
              {!disabled && (
                <Button
                  variant="ghost"
                  size="xs"
                  icon={X}
                  aria-label={`Do not ask for ${labelOf(name)}`}
                  onClick={() => {
                    const next = chosen.filter((item) => item !== name)
                    onChange(next.length ? next : undefined)
                  }}
                />
              )}
            </div>
          ))}
          {!disabled && left.length > 0 && (
            <select
              id={id}
              aria-label="Add a field to fill"
              value=""
              onChange={(event) => onChange([...chosen, event.target.value])}
              className={`${INPUT} cursor-pointer text-fg-muted`}
            >
              <option value="">+ ask for a field…</option>
              {left.map((field) => (
                <option key={field.name} value={field.name}>
                  {field.label || field.name}
                </option>
              ))}
            </select>
          )}
        </div>
      )}
    </Field>
  )
}

/** What a question asks for besides its choices: values for the playbook alone. */
function AskedFor({ value, onChange, disabled }) {
  const rows = Array.isArray(value) ? value : []
  const write = (next) => onChange(next.length ? next : undefined)
  const change = (index, patch) => write(rows.map((row, at) => (at === index ? { ...row, ...patch } : row)))
  return (
    <div className="flex flex-col gap-2">
      {rows.map((row, index) => (
        <div
          key={index}
          role="group"
          aria-label={`Asked for ${index + 1}`}
          className="flex flex-col gap-1 border border-line-soft p-2"
        >
          <div className="flex gap-1">
            <TextInput
              aria-label={`Asked for ${index + 1}: label`}
              value={row.label ?? ''}
              disabled={disabled}
              placeholder="Serial number"
              onChange={(label) => change(index, { label })}
            />
            {!disabled && (
              <Button
                variant="ghost"
                size="xs"
                icon={X}
                aria-label={`Remove what is asked for ${index + 1}`}
                onClick={() => write(rows.filter((_, at) => at !== index))}
              />
            )}
          </div>
          <div className="flex items-center gap-1">
            <TextInput
              aria-label={`Asked for ${index + 1}: name`}
              value={row.name ?? ''}
              disabled={disabled}
              placeholder="serial"
              onChange={(name) => change(index, { name: name.toLowerCase().replace(/[^a-z0-9_]/g, '_') })}
            />
            <SelectInput
              aria-label={`Asked for ${index + 1}: type`}
              value={row.type ?? 'text'}
              disabled={disabled}
              options={INPUT_TYPES}
              onChange={(type) => change(index, { type })}
            />
          </div>
          <Switch
            label="Needed"
            checked={Boolean(row.required)}
            disabled={disabled}
            onChange={(required) => change(index, { required })}
          />
        </div>
      ))}
      {!disabled && rows.length < 10 && (
        <Button
          variant="secondary"
          size="xs"
          icon={Plus}
          className="self-start"
          onClick={() => write([...rows, { name: `value_${rows.length + 1}`, label: '', type: 'text' }])}
        >
          Ask for a value
        </Button>
      )}
    </div>
  )
}

/** An interval that can be left out: "never", or every so long. */
function Every({ label, hint, none, some, value, start, onChange, disabled }) {
  return (
    <Field label={label} hint={hint}>
      {(id) => (
        <div className="flex flex-wrap items-center gap-2">
          <Seg
            label={label}
            value={value ? 'some' : 'none'}
            disabled={disabled}
            onChange={(next) => onChange(next === 'some' ? start : undefined)}
            options={[
              { value: 'none', label: none },
              { value: 'some', label: some },
            ]}
          />
          {value ? (
            <DurationInput
              id={id}
              value={value}
              disabled={disabled}
              onChange={(seconds) => onChange(seconds ?? start)}
            />
          ) : null}
        </div>
      )}
    </Field>
  )
}

/** The settings of a task or of a question: what is asked, of whom, by when, and what is filled. */
function PersonSettings({ node, tree, disabled, onConfig, problemAt }) {
  const config = node.config ?? {}
  const task = node.kind === 'task'
  const what = task ? 'title' : 'question'
  return (
    <>
      <Field
        label={task ? 'What to do' : 'Question'}
        required
        hint={task ? 'The title of the task.' : 'What the person who answers reads.'}
        problem={problemAt(what)}
      >
        {(id) => (
          <ExpressionInput
            id={id}
            tree={tree}
            disabled={disabled}
            value={config[what] ?? ''}
            placeholder={task ? 'Collect the laptop of {{ incident.username }}' : 'Is the disk encrypted?'}
            onChange={(text) => onConfig({ [what]: text })}
          />
        )}
      </Field>
      <Field label="Instructions" hint="Shown on the page of the task. Markdown.">
        {(id) => (
          <ExpressionInput
            id={id}
            multiline
            tree={tree}
            disabled={disabled}
            value={config.instructions ?? ''}
            onChange={(instructions) => onConfig({ instructions: instructions || undefined })}
          />
        )}
      </Field>
      <Assignee
        value={config.assignee}
        tree={tree}
        disabled={disabled}
        anyone={!task}
        onChange={(assignee) => onConfig({ assignee })}
      />
      {!task && (
        <Field
          label="Choices"
          hint="One edge leaves the node for each choice. With none, the answer is the form alone."
          problem={problemAt('choices')}
        >
          {() => (
            <ListInput
              label="The choices, separated by commas"
              tree={tree}
              value={config.choices ?? []}
              disabled={disabled}
              onChange={(choices) =>
                onConfig({ choices: Array.isArray(choices) && choices.length ? choices.slice(0, 6) : undefined })
              }
            />
          )}
        </Field>
      )}
      {!task && (
        <Field label="Asks for" hint="Values the steps after read as {{ node.values.name }}.">
          {() => <AskedFor value={config.inputs} disabled={disabled} onChange={(inputs) => onConfig({ inputs })} />}
        </Field>
      )}
      <FieldsToFill
        value={config.fields}
        disabled={disabled}
        problem={problemAt('fields')}
        onChange={(fields) => onConfig({ fields })}
      />
      {task && (
        <Field
          label="Due"
          hint='In how long: 30m, 2h, 3d, or an expression. Past it the task is overdue and the "when overdue" edge is followed too.'
          problem={problemAt('due')}
        >
          {(id) => (
            <ExpressionInput
              id={id}
              tree={tree}
              disabled={disabled}
              value={config.due === undefined || config.due === null ? '' : String(config.due)}
              placeholder="No due time"
              onChange={(due) => onConfig({ due: due.trim() || undefined })}
            />
          )}
        </Field>
      )}
      <Every
        label="Reminder"
        none="None"
        some="Every"
        value={config.reminder_seconds}
        start={3600}
        disabled={disabled}
        onChange={(reminder_seconds) => onConfig({ reminder_seconds })}
      />
      {!task && (
        <Every
          label="Waits"
          hint={config.timeout_seconds ? 'Then the "no answer" edge is followed.' : 'Until someone answers.'}
          none="Without limit"
          some="For"
          value={config.timeout_seconds}
          start={86400}
          disabled={disabled}
          onChange={(timeout_seconds) => onConfig({ timeout_seconds })}
        />
      )}
    </>
  )
}

/** The settings that depend on the kind of node. */
function KindSettings({
  node,
  entry,
  tree,
  events,
  playbooks,
  connections,
  approvalDefault,
  disabled,
  onConfig,
  problemAt,
}) {
  const config = node.config ?? {}
  switch (node.kind) {
    case 'trigger': {
      const filter = config.conditions
      return (
        <>
          <SectionTitle>Starts</SectionTitle>
          <Field
            label="On an event"
            hint={
              config.event && runsOn(config)
                ? `The playbook runs when this happens in Nik, on ${objectName(runsOn(config))}.`
                : 'The playbook runs when this happens in Nik.'
            }
            problem={problemAt('event')}
          >
            {(id) => (
              <SelectInput
                id={id}
                value={config.event ?? ''}
                disabled={disabled}
                onChange={(event) =>
                  // A filter written for one event reads fields another does not have.
                  onConfig({ event: event || undefined, conditions: undefined })
                }
                options={[
                  { value: '', label: '(no event)' },
                  ...events.map((event) => ({ value: event, label: eventLabel(event) })),
                ]}
              />
            )}
          </Field>
          {config.event && (
            <>
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs text-fg-muted">Only when the event matches</span>
                <Switch
                  label="Only when the event matches"
                  checked={Boolean(filter)}
                  disabled={disabled}
                  onChange={(on) =>
                    onConfig({
                      conditions: on ? sampleFilter(config.event) : undefined,
                    })
                  }
                />
              </div>
              {filter && (
                <Conditions
                  label="Event filter"
                  value={filter}
                  tree={tree}
                  disabled={disabled}
                  onChange={(conditions) => onConfig({ conditions })}
                />
              )}
            </>
          )}
          <Field
            label="On a schedule"
            hint="Five fields, as in cron: minute hour day month weekday. Every 5 minutes at most. Empty: no schedule."
            problem={problemAt('cron')}
          >
            {(id) => (
              <TextInput
                id={id}
                value={config.cron ?? ''}
                disabled={disabled}
                placeholder="0 8 * * 1-5"
                onChange={(cron) => onConfig({ cron: cron || undefined })}
              />
            )}
          </Field>
          {config.cron && (
            <Field label="Time zone of the schedule">
              {(id) => (
                <TextInput
                  id={id}
                  value={config.timezone ?? ''}
                  disabled={disabled}
                  placeholder="UTC"
                  onChange={(timezone) => onConfig({ timezone: timezone || undefined })}
                />
              )}
            </Field>
          )}
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs text-fg-muted">
              From outside: a request to the playbook’s own address (created in its Settings)
            </span>
            <Switch
              label="Starts from outside"
              checked={Boolean(config.webhook)}
              disabled={disabled}
              onChange={(webhook) => onConfig({ webhook: webhook || undefined })}
            />
          </div>
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs text-fg-muted">
              Can be run by hand
              {runsOn(config)
                ? ` (on ${objectName(runsOn(config))})`
                : ' (on an incident, an artifact, an indicator, or on nothing)'}
            </span>
            <Switch
              label="Can be run by hand"
              checked={Boolean(config.manual)}
              disabled={disabled}
              onChange={(manual) => onConfig({ manual: manual || undefined })}
            />
          </div>
        </>
      )
    }
    case 'condition':
      return (
        <>
          <SectionTitle>Goes “yes” when</SectionTitle>
          <Conditions
            label="Condition"
            value={config}
            tree={tree}
            disabled={disabled}
            onChange={(next) => onConfig({ all: undefined, any: undefined, ...next })}
          />
        </>
      )
    case 'for_each':
      return (
        <>
          <Field
            label="For each item of"
            required
            hint="An expression that gives a list. Inside the loop, {{ item }} is the item and {{ index }} its position."
            problem={problemAt('items')}
          >
            {(id) => (
              <ExpressionInput
                id={id}
                tree={tree}
                disabled={disabled}
                value={config.items ?? ''}
                placeholder="{{ search.recipients }}"
                onChange={(items) => onConfig({ items })}
              />
            )}
          </Field>
          <Field
            label="At most"
            hint="Items beyond this are left out (500 at most). Five are done at a time."
            problem={problemAt('max')}
          >
            {(id) => (
              <NumberInput
                id={id}
                value={config.max ?? 500}
                min={1}
                max={500}
                disabled={disabled}
                onChange={(max) => onConfig({ max: max ?? 500 })}
              />
            )}
          </Field>
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs text-fg-muted">Go on with the other items when one fails</span>
            <Switch
              label="Go on with the other items when one fails"
              checked={Boolean(config.continue_on_item_error)}
              disabled={disabled}
              onChange={(on) => onConfig({ continue_on_item_error: on || undefined })}
            />
          </div>
        </>
      )
    case 'wait': {
      const until = Boolean(config.until)
      return (
        <>
          <Seg
            label="What to wait for"
            value={until ? 'until' : 'time'}
            disabled={disabled}
            onChange={(next) =>
              onConfig(
                next === 'until'
                  ? {
                      seconds: undefined,
                      until: { all: [{ left: '', op: 'eq', right: '' }] },
                      every: 300,
                      timeout: 86400,
                    }
                  : { until: undefined, every: undefined, timeout: undefined, poll: undefined, seconds: 300 },
              )
            }
            options={[
              { value: 'time', label: 'For a time' },
              { value: 'until', label: 'Until a condition' },
            ]}
          />
          {until ? (
            <>
              <Conditions
                label="Wait until"
                value={config.until}
                tree={tree}
                disabled={disabled}
                onChange={(next) => onConfig({ until: next })}
              />
              <Field label="Look again every">
                {(id) => (
                  <DurationInput
                    id={id}
                    value={config.every ?? 300}
                    disabled={disabled}
                    onChange={(every) => onConfig({ every: every ?? 300 })}
                  />
                )}
              </Field>
              <Field
                label="Give up after"
                hint="Then the run goes on, and {{ this node.timed_out }} is true."
                problem={problemAt('timeout')}
              >
                {(id) => (
                  <DurationInput
                    id={id}
                    value={config.timeout ?? 86400}
                    disabled={disabled}
                    onChange={(timeout) => onConfig({ timeout: timeout ?? 86400 })}
                  />
                )}
              </Field>
            </>
          ) : (
            <Field label="Wait for" hint="Between 1 minute and 30 days." problem={problemAt('seconds')}>
              {(id) => (
                <DurationInput
                  id={id}
                  value={config.seconds ?? 300}
                  disabled={disabled}
                  onChange={(seconds) => onConfig({ seconds: seconds ?? 60 })}
                />
              )}
            </Field>
          )}
        </>
      )
    }
    case 'approval':
      return (
        <>
          <Field label="Question" required hint="What the person who answers reads." problem={problemAt('question')}>
            {(id) => (
              <ExpressionInput
                id={id}
                tree={tree}
                disabled={disabled}
                value={config.question ?? ''}
                placeholder="Open a ticket for {{ trigger.incident.name }}?"
                onChange={(question) => onConfig({ question })}
              />
            )}
          </Field>
          <Field label="Detail" hint="Shown under the question: what will be done, on what.">
            {(id) => (
              <ExpressionInput
                id={id}
                multiline
                tree={tree}
                disabled={disabled}
                value={config.detail ?? ''}
                onChange={(detail) => onConfig({ detail: detail || undefined })}
              />
            )}
          </Field>
          <ApprovalWait
            waitSeconds={config.wait_seconds}
            onExpire={config.on_expire}
            disabled={disabled}
            choices={EXPIRE_NODE}
            onChange={onConfig}
          />
        </>
      )
    case 'task':
    case 'ask':
      return <PersonSettings node={node} tree={tree} disabled={disabled} onConfig={onConfig} problemAt={problemAt} />
    case 'action':
    case 'script': {
      if (!entry) {
        return (
          <p role="alert" className="border border-high-line bg-high-soft p-2 text-xs text-high-fg">
            {node.kind === 'action'
              ? `The action "${config.action}" does not exist here.`
              : `The script "${config.script}" does not exist here.`}{' '}
            Remove the node, or bring in what it needs.
          </p>
        )
      }
      const args = config.args && typeof config.args === 'object' ? config.args : {}
      const asks = asksApproval(node, entry, approvalDefault)
      return (
        <>
          {entry.description && <p className="text-xs text-fg-muted">{entry.description}</p>}
          {entry.needsConnection && (
            <Field
              label="Connection"
              required
              hint={
                (connections[entry.connector] ?? []).length === 0
                  ? `No connection to ${entry.group} yet: one is made in Settings → Automation → Connections.`
                  : 'The system this node talks to. The playbook may reach its host.'
              }
              problem={problemAt('connection')}
            >
              {(id) => (
                <SelectInput
                  id={id}
                  value={config.connection ?? ''}
                  disabled={disabled}
                  onChange={(connection) => onConfig({ connection: connection || undefined })}
                  options={[
                    {
                      value: '',
                      label:
                        (connections[entry.connector] ?? []).length === 1 ? '(the only one)' : '(choose a connection)',
                    },
                    ...(connections[entry.connector] ?? []).map((connection) => ({
                      value: connection.name,
                      label: connection.name,
                    })),
                    ...(config.connection &&
                    !(connections[entry.connector] ?? []).some((connection) =>
                      [connection.name, connection.id].includes(config.connection),
                    )
                      ? [{ value: config.connection, label: `${config.connection} (missing)` }]
                      : []),
                  ]}
                />
              )}
            </Field>
          )}
          {entry.arguments.length > 0 && <SectionTitle>Arguments</SectionTitle>}
          {entry.arguments.map((argument) => (
            <ArgumentField
              key={argument.name}
              argument={argument}
              value={args[argument.name]}
              tree={tree}
              disabled={disabled}
              problem={problemAt(`args.${argument.name}`)}
              onChange={(value) => {
                const next = { ...args, [argument.name]: value }
                if (value === undefined || value === '') delete next[argument.name]
                onConfig({ args: next })
              }}
            />
          ))}
          <OnError config={config} onConfig={onConfig} disabled={disabled} />
          {node.kind === 'action' && (
            <>
              <SectionTitle>Approval before this node</SectionTitle>
              <div className="flex items-start gap-2">
                <Switch
                  label="Ask a person before this node runs"
                  checked={asks}
                  disabled={disabled}
                  onChange={(ask) => onConfig({ approval: { ...config.approval, ask } })}
                />
                <span className="text-xs text-fg-muted">
                  {asks ? 'Asked' : 'Not asked'}
                  {entry.changesOutside ? ' (asking is the default for what changes something outside Nik)' : ''}
                </span>
              </div>
              {asks && (
                <ApprovalWait
                  waitSeconds={config.approval?.wait_seconds}
                  onExpire={config.approval?.on_expire}
                  disabled={disabled}
                  choices={EXPIRE_INLINE}
                  onChange={(patch) => onConfig({ approval: { ...config.approval, ask: true, ...patch } })}
                />
              )}
            </>
          )}
        </>
      )
    }
    case 'playbook':
      return (
        <>
          <Field
            label="Playbook"
            required
            hint="It runs at its current version, with the inputs below."
            problem={problemAt('playbook')}
          >
            {(id) => (
              <SelectInput
                id={id}
                value={config.playbook ?? ''}
                disabled={disabled}
                onChange={(playbook) => onConfig({ playbook })}
                options={[
                  { value: '', label: '(choose a playbook)' },
                  ...playbooks.map((name) => ({ value: name, label: name })),
                  ...(config.playbook && !playbooks.includes(config.playbook)
                    ? [{ value: config.playbook, label: `${config.playbook} (missing)` }]
                    : []),
                ]}
              />
            )}
          </Field>
          <SectionTitle>Inputs given to it</SectionTitle>
          <Pairs value={config.args} tree={tree} disabled={disabled} onChange={(args) => onConfig({ args })} />
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs text-fg-muted">Wait for it to finish, and read what it gives</span>
            <Switch
              label="Wait for it to finish"
              checked={config.wait !== false}
              disabled={disabled}
              onChange={(wait) => onConfig({ wait })}
            />
          </div>
          <OnError config={config} onConfig={onConfig} disabled={disabled} />
        </>
      )
    case 'end':
      return (
        <>
          <Field label="The run ends as">
            {() => (
              <Seg
                label="The run ends as"
                value={config.status === 'failed' ? 'failed' : 'done'}
                disabled={disabled}
                onChange={(status) => onConfig({ status })}
                options={[
                  { value: 'done', label: 'Done' },
                  { value: 'failed', label: 'Failed' },
                ]}
              />
            )}
          </Field>
          <Field label="Message" hint="Shown on the run.">
            {(id) => (
              <ExpressionInput
                id={id}
                tree={tree}
                disabled={disabled}
                value={config.message ?? ''}
                onChange={(message) => onConfig({ message })}
              />
            )}
          </Field>
        </>
      )
    default:
      return null
  }
}

/** Where the node goes next, port by port; an edge can be drawn and removed here. */
function GoesTo({ graph, node, disabled, onGraph, onRefused, onSelectNode }) {
  const ports = portsOf(node)
  const outgoing = edgesFrom(graph).get(node.id) ?? []
  if (ports.length === 0) return null
  return (
    <div className="flex flex-col gap-2">
      <SectionTitle>Goes to</SectionTitle>
      {ports.map((port) => {
        const targets = outgoing.filter((edge) => edge.port === port)
        const others = graph.nodes.filter(
          (other) => other.id !== node.id && other.kind !== 'trigger' && !targets.some((edge) => edge.to === other.id),
        )
        return (
          <div key={port} role="group" aria-label={`Port ${portName(node, port)}`} className="flex flex-col gap-1">
            <span className="font-mono text-[11px] text-fg-muted">{portName(node, port)}</span>
            {targets.map((edge) => (
              <div key={edge.to} className="flex items-center justify-between gap-1 border border-line-soft pl-2">
                <button
                  type="button"
                  onClick={() => onSelectNode(edge.to)}
                  className="min-w-0 truncate py-1 text-left text-xs text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  {nodeOf(graph, edge.to)?.name || edge.to}
                </button>
                {!disabled && (
                  <Button
                    variant="ghost"
                    size="xs"
                    icon={X}
                    aria-label={`Remove the edge "${portName(node, port)}" to ${nodeOf(graph, edge.to)?.name || edge.to}`}
                    title="Remove this edge"
                    onClick={() => onGraph(disconnect(graph, node.id, port, edge.to))}
                  />
                )}
              </div>
            ))}
            {!disabled && others.length > 0 && (
              <select
                aria-label={`Draw an edge "${portName(node, port)}" to`}
                value=""
                onChange={(event) => {
                  const result = connect(graph, node.id, port, event.target.value)
                  if (result.problem) onRefused(result.problem)
                  else onGraph(result.graph)
                }}
                className={`${INPUT} cursor-pointer text-fg-muted`}
              >
                <option value="">+ draw an edge to…</option>
                {others.map((other) => (
                  <option key={other.id} value={other.id}>
                    {other.name || other.id}
                  </option>
                ))}
              </select>
            )}
          </div>
        )
      })}
    </div>
  )
}

/** The playbook itself: what it takes and what it gives back. */
function PlaybookSettings({ graph, disabled, onGraph, problems }) {
  const inputs = Array.isArray(graph.inputs) ? graph.inputs : []
  const outputs = Array.isArray(graph.outputs) ? graph.outputs : []
  const general = problems.filter((problem) => !problem.node)
  const setInputs = (next) => onGraph({ ...graph, inputs: next })
  const setOutputs = (next) => onGraph({ ...graph, outputs: next })
  return (
    <div className="flex flex-col gap-3">
      <h2 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">The playbook</h2>
      <p className="text-xs text-fg-muted">
        Select a node to set it. Drag one from the library, or click it there to add it.
      </p>
      {general.length > 0 && (
        <ul role="alert" className="flex flex-col gap-1 border border-high-line bg-high-soft p-2 text-xs text-high-fg">
          {general.map((problem, index) => (
            <li key={index}>{problem.message}</li>
          ))}
        </ul>
      )}
      <SectionTitle>Inputs</SectionTitle>
      <p className="text-xs text-fg-muted">
        What is asked when the playbook is run by hand, or given by a playbook that runs it. Read as{' '}
        {'{{ inputs.name }}'}.
      </p>
      {inputs.map((input, index) => (
        <div
          key={index}
          role="group"
          aria-label={`Input ${index + 1}`}
          className="flex flex-col gap-1 border border-line-soft p-2"
        >
          <div className="flex gap-1">
            <TextInput
              aria-label={`Input ${index + 1}: name`}
              value={input.name ?? ''}
              disabled={disabled}
              placeholder="name"
              onChange={(name) => setInputs(inputs.map((item, at) => (at === index ? { ...item, name } : item)))}
            />
            <SelectInput
              aria-label={`Input ${index + 1}: type`}
              value={input.type ?? 'text'}
              disabled={disabled}
              options={TYPES}
              onChange={(type) => setInputs(inputs.map((item, at) => (at === index ? { ...item, type } : item)))}
            />
            {!disabled && (
              <Button
                variant="ghost"
                size="xs"
                icon={Trash2}
                aria-label={`Remove input ${index + 1}`}
                onClick={() => setInputs(inputs.filter((_, at) => at !== index))}
              />
            )}
          </div>
          <label className="flex items-center gap-2 text-xs text-fg-muted">
            <input
              type="checkbox"
              checked={Boolean(input.required)}
              disabled={disabled}
              onChange={(event) =>
                setInputs(inputs.map((item, at) => (at === index ? { ...item, required: event.target.checked } : item)))
              }
              className="accent-accent"
            />
            required
          </label>
        </div>
      ))}
      {!disabled && (
        <Button
          variant="secondary"
          size="xs"
          icon={Plus}
          className="self-start"
          onClick={() => setInputs([...inputs, { name: `input_${inputs.length + 1}`, type: 'text', required: false }])}
        >
          Add an input
        </Button>
      )}
      <SectionTitle>Outputs</SectionTitle>
      <p className="text-xs text-fg-muted">What a playbook that runs this one reads when it has finished.</p>
      {outputs.map((output, index) => (
        <div
          key={index}
          role="group"
          aria-label={`Output ${index + 1}`}
          className="flex flex-col gap-1 border border-line-soft p-2"
        >
          <div className="flex gap-1">
            <TextInput
              aria-label={`Output ${index + 1}: name`}
              value={output.name ?? ''}
              disabled={disabled}
              placeholder="name"
              onChange={(name) => setOutputs(outputs.map((item, at) => (at === index ? { ...item, name } : item)))}
            />
            {!disabled && (
              <Button
                variant="ghost"
                size="xs"
                icon={Trash2}
                aria-label={`Remove output ${index + 1}`}
                onClick={() => setOutputs(outputs.filter((_, at) => at !== index))}
              />
            )}
          </div>
          <ExpressionInput
            label={`Output ${index + 1}: value`}
            disabled={disabled}
            value={output.from ?? ''}
            placeholder="{{ node.field }}"
            onChange={(from) => setOutputs(outputs.map((item, at) => (at === index ? { ...item, from } : item)))}
          />
        </div>
      ))}
      {!disabled && (
        <Button
          variant="secondary"
          size="xs"
          icon={Plus}
          className="self-start"
          onClick={() => setOutputs([...outputs, { name: `output_${outputs.length + 1}`, from: '' }])}
        >
          Add an output
        </Button>
      )}
    </div>
  )
}

/**
 * @param {{
 *   graph: object,
 *   nodeId: string | null,
 *   catalog: object[],
 *   events: string[],                 // what a trigger can wait for
 *   connections: Record<string, Array<{ id: string, name: string }>>,  // by connector
 *   playbooks: string[],              // the names a "run another playbook" node can choose
 *   problems: Array<{ message: string, node: string | null, field: string | null }>,
 *   updates: Array<{ node: string, script: string, from: number, to: number }>,
 *   approvalDefault: boolean,
 *   readOnly: boolean,
 *   onGraph: (graph: object) => void,
 *   onRenamed: (from: string, to: string) => void,
 *   onRefused: (why: string) => void,
 *   onSelectNode: (id: string) => void,
 *   onRemove: (id: string) => void,
 * }} props
 */
export default function Inspector({
  graph,
  nodeId,
  catalog,
  events,
  playbooks,
  connections,
  problems,
  updates,
  approvalDefault,
  readOnly,
  onGraph,
  onRenamed,
  onRefused,
  onSelectNode,
  onRemove,
}) {
  const node = nodeId ? nodeOf(graph, nodeId) : null
  const entry = useMemo(() => entryOf(node, catalog), [node, catalog])
  const tree = useMemo(() => (node ? valueTree(graph, node.id, catalog) : []), [graph, node, catalog])
  const [idDraft, setIdDraft] = useState(null)
  const [idProblem, setIdProblem] = useState(null)

  if (!node) {
    return (
      <aside
        aria-label="Inspector"
        className="min-h-0 w-full shrink-0 overflow-y-auto border-l border-line bg-panel p-3 md:w-[300px]"
      >
        <PlaybookSettings graph={graph} disabled={readOnly} onGraph={onGraph} problems={problems} />
      </aside>
    )
  }

  const mine = problems.filter((problem) => problem.node === node.id)
  const problemAt = (field) => mine.find((problem) => problem.field === field)?.message ?? null
  const elsewhere = mine.filter(
    (problem) =>
      !problem.field ||
      !/^(args\.|event$|cron$|items$|max$|seconds$|timeout$|question$|title$|choices$|fields$|due$|playbook$|connection$)/.test(
        problem.field,
      ),
  )
  const notReadable = unreadable(graph, node.id)
  const update = updates.find((item) => item.node === node.id)
  const onConfig = (patch) => {
    const config = { ...node.config, ...patch }
    for (const key of Object.keys(config)) if (config[key] === undefined) delete config[key]
    // A choice of a question that is gone takes its edges with it.
    onGraph(pruneEdges(updateNode(graph, node.id, { config }), node.id))
  }
  const commitId = () => {
    if (idDraft === null || idDraft === node.id) {
      setIdDraft(null)
      setIdProblem(null)
      return
    }
    const result = renameNode(graph, node.id, idDraft)
    if (result.problem) {
      setIdProblem(result.problem)
      return
    }
    setIdDraft(null)
    setIdProblem(null)
    onGraph(result.graph)
    onRenamed(node.id, idDraft)
  }
  const outputs = entry?.outputs ?? []

  return (
    <aside
      aria-label="Inspector"
      className="min-h-0 w-full shrink-0 overflow-y-auto border-l border-line bg-panel p-3 md:w-[300px]"
    >
      <div key={node.id} className="flex flex-col gap-3">
        <div className="flex items-start justify-between gap-2">
          <h2 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">
            {headingOf(node, entry)}
            {entry && node.kind === 'action' ? ` · ${entry.name}` : ''}
          </h2>
          {!readOnly && node.kind !== 'trigger' && (
            <Button
              variant="ghost"
              size="xs"
              icon={Trash2}
              aria-label="Remove this node"
              title="Remove this node (Delete)"
              onClick={() => onRemove(node.id)}
            />
          )}
        </div>

        {update && (
          <div
            role="status"
            className="flex flex-col gap-2 border border-info-line bg-info-soft/40 p-2 text-xs text-fg"
          >
            <span>
              Version {update.to} of {update.script} exists. This node stays on version {update.from} until it is
              updated.
            </span>
            {!readOnly && (
              <Button
                variant="secondary"
                size="xs"
                className="self-start"
                onClick={() => onConfig({ script_version: update.to })}
              >
                Update to version {update.to}
              </Button>
            )}
          </div>
        )}

        <Field label="Name">
          {(id) => (
            <TextInput
              id={id}
              value={node.name ?? ''}
              disabled={readOnly}
              maxLength={80}
              onChange={(name) => onGraph(updateNode(graph, node.id, { name }))}
            />
          )}
        </Field>
        <Field label="Id" hint={`What expressions call it: {{ ${idDraft ?? node.id}.… }}`} problem={idProblem}>
          {(id) => (
            <TextInput
              id={id}
              value={idDraft ?? node.id}
              disabled={readOnly}
              maxLength={32}
              onChange={(next) => {
                setIdDraft(next)
                setIdProblem(null)
              }}
              onBlur={commitId}
              onKeyDown={(event) => {
                if (event.key === 'Enter') commitId()
              }}
            />
          )}
        </Field>

        {node.kind !== 'trigger' && (
          <Field label="Phase" hint="Groups this step in the work plan of an incident: Triage, Containment…">
            {(id) => (
              <TextInput
                id={id}
                value={node.config?.phase ?? ''}
                disabled={readOnly}
                maxLength={40}
                onChange={(phase) => onConfig({ phase: phase || undefined })}
              />
            )}
          </Field>
        )}

        <KindSettings
          node={node}
          entry={entry}
          tree={tree}
          events={events}
          playbooks={playbooks}
          connections={connections}
          approvalDefault={approvalDefault}
          disabled={readOnly}
          onConfig={onConfig}
          problemAt={problemAt}
        />

        {(elsewhere.length > 0 || notReadable.length > 0) && (
          <ul
            role="alert"
            aria-label="To fix on this node"
            className="flex flex-col gap-1 border border-high-line bg-high-soft p-2 text-xs text-high-fg"
          >
            {elsewhere.map((problem, index) => (
              <li key={`p${index}`}>{problem.message}</li>
            ))}
            {notReadable
              .filter((item) => !elsewhere.some((problem) => problem.message.includes(`"${item.name}"`)))
              .map((item) => (
                <li key={item.name}>
                  “{item.name}” {item.reason}
                </li>
              ))}
          </ul>
        )}

        <GoesTo
          graph={graph}
          node={node}
          disabled={readOnly}
          onGraph={onGraph}
          onRefused={onRefused}
          onSelectNode={onSelectNode}
        />

        {outputs.length > 0 && (
          <div className="flex flex-col gap-1">
            <SectionTitle>Gives</SectionTitle>
            <ul className="flex flex-col gap-1">
              {outputs.map((output) => (
                <li key={output.name} className="text-xs">
                  <code className="break-all font-mono text-info">{`{{ ${node.id}.${output.name} }}`}</code>
                  <span className="text-fg-muted">
                    {' '}
                    {output.type}
                    {output.description ? ` · ${output.description}` : ''}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </aside>
  )
}
