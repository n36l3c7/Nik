import { useCallback, useEffect, useState } from 'react'
import { AlertCircle, Check, Pencil, Plus, Power, Radar, Trash2, X } from 'lucide-react'
import { api } from '../../../services/api.js'
import { formatRelative } from '../../../utils/time.js'
import { Badge, Button, MicroSkull } from '../../ui/index.js'

/*
 * capa rules settings section (admin only). The capa worker ships Mandiant's
 * rule set; admins add their own rules here, one capa rule (YAML) each.
 * Every rule is checked by the worker against the bundled rules and the
 * other admin rules before it is saved (syntax, features, unique name,
 * `match:` dependencies), so a broken rule never stops capa. Rules apply to
 * samples analysed from then on.
 */

const INPUT_CLASS =
  'w-full border border-line bg-panel px-3 py-2 font-mono text-sm text-fg ' +
  'placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

const TEMPLATE = `rule:
  meta:
    name: contact team C2 panel
    namespace: team/communication
    authors:
      - analyst@example.org
    description: What this rule detects
    scopes:
      static: function
      dynamic: process
    att&ck:
      - Command and Control::Application Layer Protocol [T1071]
  features:
    - and:
      - string: /gate\\.php/i
      - match: send HTTP request
`

export default function CapaRulesSection() {
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [editing, setEditing] = useState(null) // null | 'new' | rule id
  const [source, setSource] = useState(TEMPLATE)
  const [validation, setValidation] = useState(null) // { ok, errors, name, namespace, scope } | null
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try {
      setRules((await api.get('/capa-rules')).rules)
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const edit = (rule) => {
    setEditing(rule ? rule.id : 'new')
    setSource(rule ? rule.source : TEMPLATE)
    setValidation(null)
  }

  const validate = async () => {
    setBusy(true)
    setError(null)
    try {
      setValidation(await api.post('/capa-rules/validate', { source, id: editing === 'new' ? null : editing }))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const save = async () => {
    setBusy(true)
    setError(null)
    try {
      if (editing === 'new') {
        await api.post('/capa-rules', { source, enabled: true })
      } else {
        const current = rules.find((r) => r.id === editing)
        await api.put(`/capa-rules/${editing}`, { source, enabled: current?.enabled ?? true })
      }
      setEditing(null)
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const toggle = async (rule) => {
    setError(null)
    try {
      await api.put(`/capa-rules/${rule.id}`, { source: rule.source, enabled: !rule.enabled })
      await load()
    } catch (err) {
      setError(err.message)
    }
  }

  const remove = async (rule) => {
    setError(null)
    try {
      await api.del(`/capa-rules/${rule.id}`)
      await load()
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <section className="space-y-6">
      <div>
        <h2 className="flex items-center gap-2 text-base font-semibold text-fg">
          <Radar className="h-4 w-4 text-accent" aria-hidden="true" />
          capa rules
        </h2>
        <p className="mt-1 text-sm text-fg-muted">
          capa runs Mandiant&apos;s rule set on every executable sample; add your own rules here, one{' '}
          <a
            href="https://github.com/mandiant/capa-rules/blob/master/doc/format.md"
            target="_blank"
            rel="noreferrer"
            className="text-accent-fg underline"
          >
            capa rule
          </a>{' '}
          each. The capa worker checks a rule against the bundled ones and yours before it is saved, so it needs to be
          running. Rules apply to samples analysed from now on: use <em>Re-analyse</em> on older ones.
        </p>
      </div>

      {error && (
        <p
          role="alert"
          className="flex items-center gap-2 border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg"
        >
          <AlertCircle className="h-4 w-4 shrink-0" aria-hidden="true" />
          {error}
        </p>
      )}

      <div className="space-y-2">
        <div className="flex items-center justify-between gap-3">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-fg-muted">Your rules · {rules.length}</h3>
          {editing === null && (
            <Button size="sm" icon={Plus} onClick={() => edit(null)}>
              Add rule
            </Button>
          )}
        </div>

        {loading ? (
          <p className="flex items-center gap-2 font-mono text-sm text-fg-muted">
            <MicroSkull /> loading…
          </p>
        ) : rules.length === 0 && editing === null ? (
          <p className="text-sm text-fg-muted">No admin rules yet: capa uses its bundled rule set.</p>
        ) : (
          <ul className="space-y-2">
            {rules.map((rule) => (
              <li
                key={rule.id}
                className="flex flex-wrap items-center justify-between gap-2 border border-line bg-panel px-3 py-2.5"
              >
                <span className="flex min-w-0 flex-wrap items-center gap-2 font-mono text-sm">
                  <span className="font-semibold text-fg">{rule.name}</span>
                  <Badge color={rule.enabled ? 'emerald' : 'slate'}>{rule.enabled ? 'enabled' : 'disabled'}</Badge>
                  <span className="text-xs text-fg-muted">
                    {rule.namespace || 'no namespace'} · {rule.scope} · {rule.createdBy} ·{' '}
                    {formatRelative(rule.updatedAt)}
                  </span>
                </span>
                <span className="flex items-center gap-1">
                  <Button
                    variant="ghost"
                    size="xs"
                    icon={Pencil}
                    onClick={() => edit(rule)}
                    aria-label={`Edit ${rule.name}`}
                  >
                    Edit
                  </Button>
                  <Button
                    variant="ghost"
                    size="xs"
                    icon={Power}
                    onClick={() => toggle(rule)}
                    aria-label={`${rule.enabled ? 'Disable' : 'Enable'} ${rule.name}`}
                  >
                    {rule.enabled ? 'Disable' : 'Enable'}
                  </Button>
                  <Button
                    variant="ghost"
                    size="xs"
                    icon={Trash2}
                    onClick={() => remove(rule)}
                    aria-label={`Delete ${rule.name}`}
                  >
                    Delete
                  </Button>
                </span>
              </li>
            ))}
          </ul>
        )}

        {editing !== null && (
          <form
            className="space-y-3 border border-accent-strong bg-canvas p-3"
            onSubmit={(event) => {
              event.preventDefault()
              save()
            }}
          >
            <div>
              <label htmlFor="capa-source" className="mb-1 block font-mono text-xs text-fg-muted">
                capa rule (YAML)
              </label>
              <textarea
                id="capa-source"
                value={source}
                onChange={(event) => {
                  setSource(event.target.value)
                  setValidation(null)
                }}
                rows={18}
                spellCheck={false}
                className={`${INPUT_CLASS} resize-y text-xs leading-relaxed`}
              />
            </div>
            {validation && (
              <p
                role="status"
                className={`flex items-start gap-2 border px-3 py-2 font-mono text-xs ${
                  validation.ok
                    ? 'border-accent-strong bg-accent-soft text-accent-fg'
                    : 'border-high-line bg-high-soft text-high-fg'
                }`}
              >
                {validation.ok ? <Check className="h-4 w-4 shrink-0" /> : <AlertCircle className="h-4 w-4 shrink-0" />}
                <span>
                  {validation.ok
                    ? `Valid: ${validation.name} (${validation.namespace || 'no namespace'}, ${validation.scope} scope)`
                    : validation.errors.join('; ')}
                </span>
              </p>
            )}
            <div className="flex flex-wrap items-center gap-2">
              <Button type="submit" size="sm" disabled={busy || !source.trim()}>
                {busy ? 'Checking…' : editing === 'new' ? 'Save rule' : 'Save changes'}
              </Button>
              <Button type="button" variant="secondary" size="sm" onClick={validate} disabled={busy}>
                Validate
              </Button>
              <Button type="button" variant="ghost" size="sm" icon={X} onClick={() => setEditing(null)}>
                Cancel
              </Button>
            </div>
          </form>
        )}
      </div>
    </section>
  )
}
