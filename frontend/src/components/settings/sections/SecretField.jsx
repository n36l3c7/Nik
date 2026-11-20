import {
  mentionsCredential,
  parseReference,
  pickedReference,
  pickerOptions,
  storedReference,
} from '../../../domain/automation/credentials.js'
import { credentialPath } from '../../../domain/settingsNav.js'
import { setPath } from '../../../lib/location.js'
import { Button } from '../../ui/index.js'

/*
 * One secret of an instance, in its form: a part of its credentials, on the
 * Connection tab or in one of its other keys.
 *
 * It is given in one of two ways. Typed here, as always: the value is stored
 * with the instance and never shown again. Or from a credential (Settings →
 * Credentials): the field then holds the name of the credential, shown with a
 * link to it, and never its value. A pair chosen for a user name or a
 * password fills both. The way is chosen only when there is a credential to
 * choose: without any, the field is the one it always was.
 *
 * The form that holds the field keeps what it edits (`value` is what was
 * typed, or the text that names a credential) and what is stored comes from
 * the server (`stored`, and `held`: the credential the field is stored with).
 */

/**
 * @param {{
 *   id: string,
 *   label: string,
 *   masked?: boolean,
 *   inputClass: string,
 *   value: string,                          // what the form holds for the field
 *   onValue: (text: string) => void,
 *   onFill: (fills: object) => void,        // a credential was chosen: every field it sets
 *   mode: 'typed' | 'credential',
 *   onMode: (mode: string) => void,
 *   stored?: boolean,                       // the instance has something for the field
 *   held?: object,                          // { field: { name, part, missing } } of the instance or the key
 *   field: string,
 *   choices: object[],                      // as `credentialChoices` gives them
 *   removed?: boolean,
 *   onRemove?: () => void,
 *   onKeep?: () => void,                    // "Keep as a credential…", when the stored value was typed
 *   help?: string,
 * }} props
 */
export default function SecretField({
  id,
  label,
  masked = true,
  inputClass,
  value,
  onValue,
  onFill,
  mode,
  onMode,
  stored = false,
  held,
  field,
  choices,
  removed = false,
  onRemove,
  onKeep,
  help = '',
}) {
  const reference = storedReference(held, field)
  const picked = pickedReference(value, reference)
  const named = parseReference(picked)
  const options = pickerOptions(choices, picked, held?.[field])
  const offered = choices.length > 0 || Boolean(reference) || mode === 'credential'
  const lower = label.toLowerCase()

  return (
    <div className="flex flex-col gap-1">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <label className="text-fg-muted" htmlFor={id}>
          {label}
          {stored && !removed && (
            <span className="ml-2 font-mono text-[11px] text-accent-fg">
              {reference ? 'from a credential' : 'stored'}
            </span>
          )}
          {removed && <span className="ml-2 font-mono text-[11px] text-high-fg">will be removed</span>}
        </label>
        <span className="flex-1" />
        {offered && (
          <select
            aria-label={`How the ${lower} is given`}
            value={mode}
            onChange={(event) => onMode(event.target.value)}
            className="cursor-pointer border border-line bg-canvas px-1.5 py-0.5 text-xs text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <option value="credential">From a credential</option>
            <option value="typed">Typed here</option>
          </select>
        )}
      </div>
      {mode === 'credential' ? (
        <div className="flex items-center gap-2">
          <select
            id={id}
            aria-label={`Credential for the ${lower}`}
            value={picked}
            onChange={(event) => {
              const choice = options.find((option) => option.value === event.target.value)
              if (choice && Object.keys(choice.fills).length > 0) onFill(choice.fills)
            }}
            className={`${inputClass} cursor-pointer`}
          >
            {!picked && <option value="">Choose a credential…</option>}
            {options.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          {named && (
            <a
              href={credentialPath(named.name)}
              aria-label={`Open the credential ${named.name}`}
              onClick={(event) => {
                event.preventDefault()
                setPath(credentialPath(named.name))
              }}
              className="shrink-0 text-xs text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              Open
            </a>
          )}
        </div>
      ) : (
        <div className="flex flex-wrap gap-2">
          <input
            id={id}
            // A credential written by hand is a name, not a secret: it is shown as it is typed.
            type={masked && !mentionsCredential(value) ? 'password' : 'text'}
            value={value ?? ''}
            autoComplete={masked ? 'new-password' : 'off'}
            spellCheck={false}
            placeholder={
              stored && !removed
                ? reference
                  ? `from ${parseReference(reference).name}: type to replace it`
                  : 'stored: type to replace it'
                : ''
            }
            onChange={(event) => onValue(event.target.value)}
            className={`${inputClass} min-w-0 flex-1`}
          />
          {stored && !removed && onRemove && (
            <Button variant="secondary" size="sm" aria-label={`Remove the stored ${lower}`} onClick={onRemove}>
              Remove
            </Button>
          )}
          {stored && !removed && onKeep && (
            <Button
              variant="secondary"
              size="sm"
              aria-label={`Keep the ${lower} as a credential`}
              title="Move the stored value to Settings, Credentials, under a name: this instance then names it"
              onClick={onKeep}
            >
              Keep as a credential…
            </Button>
          )}
        </div>
      )}
      {held?.[field]?.missing && (
        <p role="alert" className="text-xs text-high-fg">
          The credential “{held[field].name}” does not exist any more: the instance fails until it is made again, or
          another is given here.
        </p>
      )}
      {help && <span className="text-xs text-fg-muted">{help}</span>}
    </div>
  )
}
