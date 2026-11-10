import { useCallback, useEffect, useState } from 'react'
import { AlertCircle, Check, FileSearch, Pencil, Plus, Power, Trash2, X } from 'lucide-react'
import { api } from '../../../services/api.js'
import { formatRelative } from '../../../lib/time.js'
import { Badge, Button, MicroSkull } from '../../ui/index.js'

/*
 * YARA rules settings section (admin only). Nik ships a built-in rule set;
 * admins add their own sources here. Each source is compiled on the server
 * before it is saved, so a broken rule never reaches the shared scan. Rules
 * run on every sample upload and on "Re-analyse"; the sample's YARA view
 * reads `severity` and `description` from each rule's meta.
 */

const INPUT_CLASS =
  'w-full border border-line bg-panel px-3 py-2 font-mono text-sm text-fg ' +
  'placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

const TEMPLATE = `rule team_marker
{
    meta:
        description = "What this rule detects"
        severity = "high"
    strings:
        $a = "suspicious string" ascii wide nocase
    condition:
        $a
}
`

export default function YaraRulesSection() {
  const [rules, setRules] = useState([])
  const [builtin, setBuiltin] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [editing, setEditing] = useState(null) // null | 'new' | rule id
  const [name, setName] = useState('')
  const [source, setSource] = useState(TEMPLATE)
  const [validation, setValidation] = useState(null) // { ok, errors, ruleNames } | null
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    try {
      const data = await api.get('/yara-rules')
      setRules(data.rules)
      setBuiltin(data.builtin)
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

  const startNew = () => {
    setEditing('new')
    setName('')
    setSource(TEMPLATE)
    setValidation(null)
  }

  const startEdit = (rule) => {
    setEditing(rule.id)
    setName(rule.name)
    setSource(rule.source)
    setValidation(null)
  }

  const cancel = () => {
    setEditing(null)
    setValidation(null)
  }

  const validate = async () => {
    try {
      setValidation(await api.post('/yara-rules/validate', { name: name || 'draft', source }))
    } catch (err) {
      setError(err.message)
    }
  }

  const save = async () => {
    setSaving(true)
    setError(null)
    try {
      const body = { name: name.trim(), source, enabled: true }
      if (editing === 'new') {
        await api.post('/yara-rules', body)
      } else {
        const current = rules.find((r) => r.id === editing)
        await api.put(`/yara-rules/${editing}`, { ...body, enabled: current?.enabled ?? true })
      }
      setEditing(null)
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  const toggle = async (rule) => {
    setError(null)
    try {
      await api.put(`/yara-rules/${rule.id}`, { name: rule.name, source: rule.source, enabled: !rule.enabled })
      await load()
    } catch (err) {
      setError(err.message)
    }
  }

  const remove = async (rule) => {
    setError(null)
    try {
      await api.del(`/yara-rules/${rule.id}`)
      await load()
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <section className="space-y-6">
      <div>
        <h2 className="flex items-center gap-2 text-base font-semibold text-fg">
          <FileSearch className="h-4 w-4 text-accent" aria-hidden="true" />
          YARA rules
        </h2>
        <p className="mt-1 text-sm text-fg-muted">
          Run on every malware sample at upload and on re-analysis. Put <code>severity</code> (<code>high</code> or{' '}
          <code>medium</code>) and <code>description</code> in each rule's <code>meta</code>: the sample view shows
          both. New rules apply to samples analysed from now on; use <em>Re-analyse</em> on older ones.
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

      {/* Built-in rules (read only) */}
      <div className="space-y-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-fg-muted">Built-in rule files</h3>
        {builtin.length === 0 && !loading && (
          <p className="text-sm text-fg-muted">No built-in rule file found on the server.</p>
        )}
        <ul className="space-y-1">
          {builtin.map((file) => (
            <li key={file.namespace} className="border border-line bg-panel px-3 py-2 font-mono text-xs">
              <span className="text-fg">{file.namespace.replace('builtin:', '')}.yar</span>
              <span className="text-fg-muted"> · {file.ruleNames.length} rules: </span>
              <span className="text-fg-muted">{file.ruleNames.join(', ')}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* Admin rules */}
      <div className="space-y-2">
        <div className="flex items-center justify-between gap-3">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-fg-muted">
            Your rule sets · {rules.length}
          </h3>
          {editing === null && (
            <Button size="sm" icon={Plus} onClick={startNew}>
              Add rule set
            </Button>
          )}
        </div>

        {loading ? (
          <p className="flex items-center gap-2 font-mono text-sm text-fg-muted">
            <MicroSkull /> loading…
          </p>
        ) : rules.length === 0 && editing === null ? (
          <p className="text-sm text-fg-muted">No admin rules yet. Add a rule set to extend the built-in detection.</p>
        ) : (
          <ul className="space-y-2">
            {rules.map((rule) => (
              <li key={rule.id} className="border border-line bg-panel px-3 py-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="flex min-w-0 flex-wrap items-center gap-2 font-mono text-sm">
                    <span className="font-semibold text-fg">{rule.name}</span>
                    <Badge color={rule.enabled ? 'emerald' : 'slate'}>{rule.enabled ? 'enabled' : 'disabled'}</Badge>
                    <span className="text-xs text-fg-muted">
                      {rule.ruleNames.length} rule{rule.ruleNames.length === 1 ? '' : 's'} · {rule.createdBy} ·{' '}
                      {formatRelative(rule.updatedAt)}
                    </span>
                  </span>
                  <span className="flex items-center gap-1">
                    <Button
                      variant="ghost"
                      size="xs"
                      icon={Pencil}
                      onClick={() => startEdit(rule)}
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
                </div>
                <p className="mt-1 font-mono text-xs text-fg-muted">{rule.ruleNames.join(', ')}</p>
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
              <label htmlFor="yara-name" className="mb-1 block font-mono text-xs text-fg-muted">
                Rule set name
              </label>
              <input
                id="yara-name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="e.g. Team IOC rules"
                className={INPUT_CLASS}
                required
              />
            </div>
            <div>
              <label htmlFor="yara-source" className="mb-1 block font-mono text-xs text-fg-muted">
                YARA source
              </label>
              <textarea
                id="yara-source"
                value={source}
                onChange={(event) => {
                  setSource(event.target.value)
                  setValidation(null)
                }}
                rows={14}
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
                    ? `Compiles: ${validation.ruleNames.join(', ') || 'no rule declared'}`
                    : validation.errors.join('; ')}
                </span>
              </p>
            )}
            <div className="flex flex-wrap items-center gap-2">
              <Button type="submit" size="sm" disabled={saving || !name.trim()}>
                {saving ? 'Saving…' : editing === 'new' ? 'Save rule set' : 'Save changes'}
              </Button>
              <Button type="button" variant="secondary" size="sm" onClick={validate}>
                Validate
              </Button>
              <Button type="button" variant="ghost" size="sm" icon={X} onClick={cancel}>
                Cancel
              </Button>
            </div>
          </form>
        )}
      </div>
    </section>
  )
}
