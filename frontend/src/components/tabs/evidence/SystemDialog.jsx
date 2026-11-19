import { useRef, useState } from 'react'
import { OS_LIST, getOsById } from '../../../config/os.js'
import { useLayer } from '../../../lib/layers.js'
import { Button } from '../../ui/index.js'

/*
 * ============================================================================
 * WHICH SYSTEM — asked before a kind of evidence that depends on it (6.2)
 * ============================================================================
 *
 * Endpoint, Event logs, Browser and Commands show the paths and the
 * collection commands of one operating system. An incident need not name one
 * (5.3); until 6.2 those pages then showed the paths of Windows, as if it had
 * been said. Now the incident is asked, once: the answer is saved on it, and
 * can be changed in "Edit the incident".
 *
 * The dialog is not one to dismiss: Escape and a click outside do nothing.
 * It is left by choosing a system, or by "Back to the files", which leaves
 * the kind for the list of evidence. Someone who may not change the incident
 * is told why nothing is shown, and can only go back.
 */

const NOTHING = () => {}
// The order of the question, and what tells the three apart at a glance.
const CHOICES = [
  { id: 'windows', hint: 'C:\\Users\\… · PowerShell' },
  { id: 'linux', hint: '/home/… · bash' },
  { id: 'macos', hint: '/Users/… · zsh' },
].filter((choice) => OS_LIST.some((os) => os.id === choice.id))

/**
 * @param {{
 *   kind: { id: string, label: string },   // the kind of evidence that asks
 *   canEdit: boolean,                      // whether the account may change the incident
 *   onBack: () => void,                    // leave the kind: back to the list of evidence
 *   onUse: (os: string) => void,           // save the system on the incident
 * }} props
 */
export default function SystemDialog({ kind, canEdit, onBack, onUse }) {
  const ref = useRef(null)
  const [chosen, setChosen] = useState(CHOICES[0].id)
  // A layer like any dialog (Tab stays inside, the focus comes back), whose Escape closes nothing.
  useLayer(ref, { open: true, onClose: NOTHING })
  const label = getOsById(chosen)?.label ?? chosen

  return (
    <div
      ref={ref}
      role="dialog"
      aria-modal="true"
      aria-label="Which system is this incident about?"
      tabIndex={-1}
      className="fixed inset-0 z-50 flex items-center justify-center bg-sunken/70 p-4 backdrop-blur-sm focus:outline-none"
    >
      <div className="flex max-h-[85vh] w-full max-w-xl flex-col overflow-hidden border border-line bg-panel shadow-2xl">
        <header className="border-b border-line px-5 py-3">
          <h2 className="font-mono text-sm font-semibold text-fg">Which system is this incident about?</h2>
          <p className="mt-1 text-sm text-fg-muted">
            Endpoint, Event logs, Browser and Commands show the paths and the collection commands of one system. This
            incident has none set, and {kind.label} cannot be shown without it.
          </p>
        </header>
        <div className="flex flex-col gap-3 overflow-y-auto p-5 text-sm">
          {canEdit ? (
            <>
              <div role="group" aria-label="System" className="flex flex-wrap gap-2">
                {CHOICES.map((choice) => {
                  const os = getOsById(choice.id)
                  const Icon = os.icon
                  const on = choice.id === chosen
                  return (
                    <button
                      key={choice.id}
                      type="button"
                      aria-pressed={on}
                      onClick={() => setChosen(choice.id)}
                      className={[
                        'flex min-w-[9rem] flex-1 flex-col items-start gap-1.5 border px-3 py-4 text-left transition-colors',
                        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                        on ? 'border-accent-strong bg-accent-soft' : 'border-line bg-canvas hover:bg-raised',
                      ].join(' ')}
                    >
                      <span className={`flex items-center gap-2 font-medium ${on ? 'text-accent-fg' : 'text-fg'}`}>
                        <Icon className={`h-4 w-4 ${on ? '' : os.accent}`} aria-hidden="true" />
                        {os.label}
                      </span>
                      <span className="font-mono text-[11px] text-fg-muted">{choice.hint}</span>
                    </button>
                  )
                })}
              </div>
              <p className="text-xs text-fg-muted">
                It is saved on the incident and can be changed in “Edit the incident”. Escape and a click outside do not
                close this dialog.
              </p>
            </>
          ) : (
            <p role="note" className="text-fg">
              Your roles do not include changing an incident: someone who may sets its system in “Edit the incident”,
              and these pages show what was collected from then on.
            </p>
          )}
        </div>
        <footer className="flex items-center justify-end gap-2 border-t border-line px-5 py-3">
          <Button variant="secondary" onClick={onBack}>
            Back to the files
          </Button>
          {canEdit && <Button onClick={() => onUse(chosen)}>Use {label}</Button>}
        </footer>
      </div>
    </div>
  )
}
