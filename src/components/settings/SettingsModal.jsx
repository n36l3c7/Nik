import { useState } from 'react'
import { AlertTriangle, Plus, RotateCcw, Trash2, Clock, ShieldAlert } from 'lucide-react'
import { Badge, Button, Modal } from '../ui/index.js'
import { useSettings, isValidRegex } from '../../context/SettingsContext.jsx'

/*
 * "Platform settings" modal.
 *  - Business hours: the window beyond which events are "outside hours".
 *  - Keyword rules: add / edit / remove suspicious and high-severity keywords
 *    (changes are saved automatically and apply to all incidents).
 */

// Hour-of-day options (00:00 … 23:00).
const HOUR_OPTIONS = Array.from({ length: 24 }, (_, h) => ({
  value: String(h),
  label: `${String(h).padStart(2, '0')}:00`,
}))

/* Shared style for text inputs. */
const inputBase =
  'rounded-lg border bg-white px-2.5 py-1.5 text-sm text-slate-800 placeholder:text-slate-400 ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 ' +
  'dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-500'

function HourSelect({ value, onChange }) {
  return (
    <select
      value={String(value)}
      onChange={(e) => onChange(Number(e.target.value))}
      className={`${inputBase} border-slate-200 dark:border-slate-700`}
    >
      {HOUR_OPTIONS.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  )
}

/** Row of an existing keyword rule (inline editing). */
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

export default function SettingsModal({ open, onClose }) {
  const {
    keywords,
    businessHours,
    addKeyword,
    updateKeyword,
    removeKeyword,
    resetKeywords,
    setBusinessHours,
  } = useSettings()

  // Draft for the new rule.
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
    <Modal
      open={open}
      onClose={onClose}
      title="Platform settings"
      maxWidth="max-w-3xl"
      footer={
        <Button variant="secondary" onClick={onClose}>
          Close
        </Button>
      }
    >
      <div className="space-y-8">
        {/* ---------- Business hours ---------- */}
        <section className="space-y-3">
          <div className="flex items-center gap-2">
            <Clock className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">
              Business hours
            </h3>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Events (visits and downloads) that occur <strong>outside</strong>{' '}
            this window are highlighted as a time anomaly.
          </p>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-3">
            <label className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
              From
              <HourSelect
                value={businessHours.startHour}
                onChange={(startHour) => setBusinessHours({ startHour })}
              />
            </label>
            <label className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
              to
              <HourSelect
                value={businessHours.endHour}
                onChange={(endHour) => setBusinessHours({ endHour })}
              />
            </label>
            <label className="flex cursor-pointer items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
              <input
                type="checkbox"
                checked={!!businessHours.flagWeekends}
                onChange={(e) => setBusinessHours({ flagWeekends: e.target.checked })}
                className="h-4 w-4 rounded border-slate-300 text-cyan-600 focus-visible:ring-2 focus-visible:ring-cyan-500 dark:border-slate-600 dark:bg-slate-800"
              />
              Also flag weekends
            </label>
          </div>
        </section>

        {/* ---------- Keyword rules ---------- */}
        <section className="space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
              <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">
                Detection rules (keywords)
              </h3>
              <Badge color="slate">{keywords.length}</Badge>
            </div>
            <Button variant="ghost" size="xs" icon={RotateCcw} onClick={resetKeywords}>
              Restore defaults
            </Button>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Keywords are searched (case-insensitive) in the URL, title and file
            name. The <span className="font-mono">pattern</span> is a regular
            expression: use <span className="font-mono">\b</span> for short words
            (e.g. <span className="font-mono">\btor\b</span>).
          </p>

          <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
            <table className="w-full min-w-[560px] text-left">
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
                  <KeywordRow
                    key={rule.id}
                    rule={rule}
                    onUpdate={updateKeyword}
                    onRemove={removeKeyword}
                  />
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
            <p className="mb-2 text-xs font-medium text-slate-600 dark:text-slate-300">
              Add a rule
            </p>
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
                placeholder="regex pattern (e.g. cobalt\\s?strike|meterpreter)"
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
        </section>
      </div>
    </Modal>
  )
}
