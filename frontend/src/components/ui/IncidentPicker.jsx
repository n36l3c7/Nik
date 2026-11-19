import { useId, useMemo, useState } from 'react'
import { X } from 'lucide-react'
import { suggestIncidents } from '../../domain/incidentName.js'
import IncidentNumber from './IncidentNumber.jsx'

/**
 * Choose an incident by typing: its number (`42`, `#42`) or words of its
 * name. Ten suggestions at most, the most likely first; arrows and Enter
 * choose, Escape closes. Never a list of every incident to scroll through.
 *
 * @param {{
 *   id?: string,
 *   incidents: { id: string, number?: number | null, name: string, status?: string }[],
 *   value: string,                       // the id of the chosen incident, or ''
 *   onChange: (id: string) => void,
 *   placeholder?: string,
 * }} props
 */
export default function IncidentPicker({ id, incidents, value, onChange, placeholder = 'Type a title or a number' }) {
  const own = useId()
  const inputId = id ?? own
  const [text, setText] = useState('')
  const [active, setActive] = useState(0)
  const [open, setOpen] = useState(false)
  const chosen = useMemo(() => incidents.find((incident) => incident.id === value) ?? null, [incidents, value])
  const found = useMemo(() => suggestIncidents(incidents, text), [incidents, text])

  const pick = (incident) => {
    onChange(incident.id)
    setText('')
    setOpen(false)
  }

  if (chosen) {
    return (
      <div
        id={inputId}
        data-incident={chosen.id}
        className="flex items-center gap-2 border border-line bg-canvas px-3 py-1.5 text-sm text-fg"
      >
        <IncidentNumber number={chosen.number} className="text-xs" />
        <span className="min-w-0 flex-1 truncate">{chosen.name}</span>
        <button
          type="button"
          aria-label="Choose another incident"
          title="Choose another, or none"
          onClick={() => onChange('')}
          className="text-fg-muted hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>
    )
  }

  return (
    <div className="relative">
      <input
        id={inputId}
        type="text"
        role="combobox"
        aria-expanded={open && found.length > 0}
        aria-controls={`${inputId}-list`}
        aria-activedescendant={open && found[active] ? `${inputId}-option-${active}` : undefined}
        aria-autocomplete="list"
        value={text}
        autoComplete="off"
        spellCheck={false}
        placeholder={placeholder}
        onChange={(event) => {
          setText(event.target.value)
          setActive(0)
          setOpen(true)
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onKeyDown={(event) => {
          if (event.key === 'ArrowDown') {
            event.preventDefault()
            setOpen(true)
            setActive((current) => Math.min(current + 1, found.length - 1))
          } else if (event.key === 'ArrowUp') {
            event.preventDefault()
            setActive((current) => Math.max(current - 1, 0))
          } else if (event.key === 'Enter' && open && found[active]) {
            event.preventDefault()
            pick(found[active])
          } else if (event.key === 'Escape' && open) {
            event.stopPropagation()
            setOpen(false)
          }
        }}
        className="w-full border border-line bg-canvas px-3 py-1.5 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      />
      {open && (
        <ul
          id={`${inputId}-list`}
          role="listbox"
          aria-label="Incidents that match"
          className="absolute inset-x-0 top-full z-20 max-h-72 overflow-y-auto border border-line bg-panel shadow-xl"
        >
          {found.length === 0 && (
            <li className="px-3 py-2 text-xs text-fg-muted">
              {text.trim() ? 'No incident matches.' : 'There is no incident yet.'}
            </li>
          )}
          {found.map((incident, index) => (
            <li
              key={incident.id}
              id={`${inputId}-option-${index}`}
              role="option"
              aria-selected={index === active}
              // The pointer goes down before the input loses the focus: the choice is made first.
              onMouseDown={(event) => {
                event.preventDefault()
                pick(incident)
              }}
              onMouseEnter={() => setActive(index)}
              className={`flex cursor-pointer items-baseline gap-2 px-3 py-1.5 text-sm ${index === active ? 'bg-accent-soft text-fg' : 'text-fg'}`}
            >
              <IncidentNumber number={incident.number} className="text-xs" />
              <span className="min-w-0 flex-1 truncate">{incident.name}</span>
              {incident.status && (
                <span className="font-mono text-[10px] text-fg-muted">{incident.status.replace('_', ' ')}</span>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
