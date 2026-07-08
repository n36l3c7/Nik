import { useState } from 'react'
import { AlertTriangle, Plus, RotateCcw, ShieldAlert, Trash2 } from 'lucide-react'
import { Badge, Button } from '../../ui/index.js'
import { useSettings, isValidRegex } from '../../../context/SettingsContext.jsx'
import {
  DEFAULT_COMMAND_KEYWORDS,
  DEFAULT_ARTIFACT_KEYWORDS,
} from '../../../config/detectionRules.js'

/*
 * Detection-rules settings section: the user-editable keyword rules, plus a
 * read-only reference of the built-in command and endpoint-artifact rulesets.
 * Extracted from the old cramped SettingsModal into a full-width section with
 * room to work.
 */

const inputBase =
  'rounded-lg border bg-white px-2.5 py-1.5 text-sm text-slate-800 placeholder:text-slate-400 ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 ' +
  'dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-500'

function KeywordRow({ rule, onUpdate, onRemove }) {
  const validPattern = isValidRegex(rule.pattern)
  return (
    <tr className="border-b border-slate-100 last:border-0 dark:border-slate-800/70">
      <td className="py-2 pr-2">
        <input
          type="text"
          value={rule.label}
          onChange={(e) => onUpdate(rule.id, { label: e.target.value })}
          className={`${inputBase} w-full border-slate-200 dark:border-slate-700`}
          aria-label="Rule label"
        />
      </td>
      <td className="py-2 pr-2">
        <input
          type="text"
          value={rule.pattern}
          onChange={(e) => onUpdate(rule.id, { pattern: e.target.value })}
          className={[
            inputBase,
            'w-full font-mono text-xs',
            validPattern
              ? 'border-slate-200 dark:border-slate-700'
              : 'border-red-400 dark:border-red-500',
          ].join(' ')}
          aria-label="Pattern (regular expression)"
          title={validPattern ? undefined : 'Invalid regular expression'}
        />
      </td>
      <td className="py-2 pr-2">
        <select
          value={rule.severity}
          onChange={(e) => onUpdate(rule.id, { severity: e.target.value })}
          className={`${inputBase} border-slate-200 dark:border-slate-700`}
          aria-label="Severity"
        >
          <option value="medium">Suspicious</option>
          <option value="high">High</option>
        </select>
      </td>
      <td className="py-2 text-right">
        <button
          type="button"
          onClick={() => onRemove(rule.id)}
          aria-label={`Remove rule ${rule.label}`}
          title="Remove rule"
          className="rounded-md p-1.5 text-slate-400 transition-colors hover:bg-red-500/10 hover:text-red-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 dark:text-slate-500 dark:hover:text-red-400"
        >
          <Trash2 className="h-4 w-4" />
        </button>
      </td>
    </tr>
  )
}

/** Read-only reference table for a built-in ruleset. */
function BuiltinRuleset({ title, description, rules }) {
  return (
    <details className="rounded-lg border border-slate-200 dark:border-slate-800">
      <summary className="flex cursor-pointer items-center gap-2 px-3 py-2.5 text-sm font-medium text-slate-700 dark:text-slate-200">
        {title}
        <Badge color="slate">{rules.length}</Badge>
        <span className="ml-auto text-xs font-normal text-slate-400 dark:text-slate-500">
          built-in · read-only
        </span>
      </summary>
      <div className="border-t border-slate-200 px-3 py-2 dark:border-slate-800">
        <p className="mb-2 text-xs text-slate-500 dark:text-slate-400">{description}</p>
        <ul className="space-y-1.5">
          {rules.map((rule) => (
            <li key={rule.id} className="flex items-start gap-2 text-xs">
              <Badge color={rule.severity === 'high' ? 'red' : 'amber'}>{rule.label}</Badge>
              <span className="text-slate-500 dark:text-slate-400">{rule.description}</span>
            </li>
          ))}
        </ul>
      </div>
    </details>
  )
}

export default function DetectionRulesSection() {
  const { keywords, addKeyword, updateKeyword, removeKeyword, resetKeywords } = useSettings()
  const [draft, setDraft] = useState({ label: '', pattern: '', severity: 'medium' })

  const draftPatternValid = draft.pattern.trim() === '' || isValidRegex(draft.pattern)
  const canAdd = draft.pattern.trim() !== '' && isValidRegex(draft.pattern)

  const handleAdd = () => {
    if (!canAdd) return
    addKeyword({
      label: draft.label.trim() || draft.pattern.trim(),
      pattern: draft.pattern.trim(),
      severity: draft.severity,
      description: 'User-defined rule.',
    })
    setDraft({ label: '', pattern: '', severity: 'medium' })
  }

  return (
    <section className="space-y-5">
      <div>
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-cyan-600 dark:text-cyan-400" />
            <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">
              Detection rules
            </h2>
            <Badge color="slate">{keywords.length}</Badge>
          </div>
          <Button variant="ghost" size="sm" icon={RotateCcw} onClick={resetKeywords}>
            Restore defaults
          </Button>
        </div>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Your keyword rules are matched (case-insensitive) against browser URLs/titles, downloaded
          file names, shell commands and endpoint artifact paths. The{' '}
          <span className="font-mono">pattern</span> is a regular expression — use{' '}
          <span className="font-mono">\b</span> for short words (e.g.{' '}
          <span className="font-mono">\btor\b</span>).
        </p>
      </div>

      <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
        <table className="w-full min-w-[640px] text-left">
          <thead>
            <tr className="border-b border-slate-200 text-xs uppercase tracking-wider text-slate-500 dark:border-slate-800 dark:text-slate-400">
              <th className="px-3 py-2 font-semibold">Label</th>
              <th className="px-3 py-2 font-semibold">Pattern (regex)</th>
              <th className="px-3 py-2 font-semibold">Severity</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody className="px-3">
            {keywords.map((rule) => (
              <KeywordRow key={rule.id} rule={rule} onUpdate={updateKeyword} onRemove={removeKeyword} />
            ))}
            {keywords.length === 0 && (
              <tr>
                <td colSpan={4} className="px-3 py-6 text-center text-sm text-slate-500 dark:text-slate-400">
                  No rules. Add one below or restore the defaults.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* New rule */}
      <div className="rounded-lg border border-dashed border-slate-300 p-3 dark:border-slate-700">
        <p className="mb-2 text-xs font-medium text-slate-600 dark:text-slate-300">Add a rule</p>
        <div className="flex flex-wrap items-start gap-2">
          <input
            type="text"
            value={draft.label}
            onChange={(e) => setDraft((d) => ({ ...d, label: e.target.value }))}
            placeholder="Label (e.g. RAT/C2)"
            className={`${inputBase} flex-1 border-slate-200 dark:border-slate-700`}
          />
          <input
            type="text"
            value={draft.pattern}
            onChange={(e) => setDraft((d) => ({ ...d, pattern: e.target.value }))}
            placeholder="regex pattern (e.g. cobalt\s?strike|meterpreter)"
            className={[
              inputBase,
              'flex-1 font-mono text-xs',
              draftPatternValid
                ? 'border-slate-200 dark:border-slate-700'
                : 'border-red-400 dark:border-red-500',
            ].join(' ')}
          />
          <select
            value={draft.severity}
            onChange={(e) => setDraft((d) => ({ ...d, severity: e.target.value }))}
            className={`${inputBase} border-slate-200 dark:border-slate-700`}
          >
            <option value="medium">Suspicious</option>
            <option value="high">High</option>
          </select>
          <Button icon={Plus} size="sm" onClick={handleAdd} disabled={!canAdd}>
            Add
          </Button>
        </div>
        {!draftPatternValid && (
          <p className="mt-2 flex items-center gap-1.5 text-xs text-red-600 dark:text-red-400">
            <AlertTriangle className="h-3.5 w-3.5" />
            Invalid regular expression.
          </p>
        )}
      </div>

      {/* Built-in rulesets (reference) */}
      <div className="space-y-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
          Built-in rulesets
        </h3>
        <BuiltinRuleset
          title="Command-line tradecraft"
          description="Applied to shell/PowerShell commands in addition to your keywords."
          rules={DEFAULT_COMMAND_KEYWORDS}
        />
        <BuiltinRuleset
          title="Endpoint artifact tradecraft"
          description="Applied to program-execution, persistence, file-access and USB records."
          rules={DEFAULT_ARTIFACT_KEYWORDS}
        />
      </div>
    </section>
  )
}
