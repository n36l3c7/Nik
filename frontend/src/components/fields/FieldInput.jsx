import { Plus, Trash2 } from 'lucide-react'
import { Button } from '../ui/index.js'

/*
 * The input of one field of the registry, by its type. It holds what
 * `toInput()` gives and gives back what `fromInput()` takes (domain/fields.js):
 * the form that owns it decides when a value is sent.
 *
 *   text, url, number, user, role   a line
 *   long_text, json                 a box
 *   bool                            yes / no / not set
 *   date, timer                     a date and a time, in UTC
 *   choice                          a select
 *   multi_choice                    a group of checkboxes
 *   tags                            words separated by commas
 *   indicator                       a value (its kind is guessed, the server checks)
 *   list                            a small table, one row per item
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-60'

function Rows({ id, field, value, onChange, disabled }) {
  const columns = field.options?.columns ?? []
  const rows = Array.isArray(value) ? value : []
  const setCell = (index, name, cell) =>
    onChange(rows.map((row, at) => (at === index ? { ...row, [name]: cell } : row)))
  return (
    <div className="flex flex-col gap-2">
      {rows.length > 0 && (
        <div className="overflow-x-auto border border-line">
          <table id={id} className="w-full border-collapse text-left text-xs">
            <caption className="sr-only">{field.label}</caption>
            <thead className="bg-panel font-mono text-fg-muted">
              <tr>
                {columns.map((column) => (
                  <th key={column.name} scope="col" className="border-b border-line px-2 py-1 font-normal">
                    {column.label}
                  </th>
                ))}
                <th scope="col" className="border-b border-line px-2 py-1">
                  <span className="sr-only">Remove</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={index}>
                  {columns.map((column) => (
                    <td key={column.name} className="border-b border-line-soft p-1">
                      {column.type === 'bool' ? (
                        <input
                          type="checkbox"
                          aria-label={`${column.label}, row ${index + 1}`}
                          checked={Boolean(row[column.name])}
                          disabled={disabled}
                          onChange={(event) => setCell(index, column.name, event.target.checked)}
                          className="h-4 w-4 accent-accent"
                        />
                      ) : column.type === 'choice' ? (
                        <select
                          aria-label={`${column.label}, row ${index + 1}`}
                          value={row[column.name] ?? ''}
                          disabled={disabled}
                          onChange={(event) => setCell(index, column.name, event.target.value)}
                          className={`${INPUT} cursor-pointer py-1 text-xs`}
                        >
                          <option value="">(not set)</option>
                          {(column.choices ?? []).map((choice) => (
                            <option key={choice} value={choice}>
                              {choice}
                            </option>
                          ))}
                        </select>
                      ) : (
                        <input
                          type="text"
                          aria-label={`${column.label}, row ${index + 1}`}
                          value={row[column.name] ?? ''}
                          disabled={disabled}
                          autoComplete="off"
                          spellCheck={false}
                          onChange={(event) => setCell(index, column.name, event.target.value)}
                          className={`${INPUT} py-1 text-xs`}
                        />
                      )}
                    </td>
                  ))}
                  <td className="border-b border-line-soft p-1 text-right">
                    <Button
                      variant="ghost"
                      size="xs"
                      icon={Trash2}
                      aria-label={`Remove row ${index + 1}`}
                      disabled={disabled}
                      onClick={() => onChange(rows.filter((_, at) => at !== index))}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Button
        variant="secondary"
        size="xs"
        icon={Plus}
        className="self-start"
        disabled={disabled}
        onClick={() => onChange([...rows, {}])}
      >
        Add a row
      </Button>
    </div>
  )
}

/**
 * @param {{
 *   id: string,
 *   field: object,                      // a field of GET /api/fields
 *   value: any,                         // what toInput() gave, then what was typed
 *   onChange: (value: any) => void,
 *   disabled?: boolean,
 *   users?: string[],                   // the accounts a "user" field offers
 *   choices?: string[],                 // overrides the field's own (the close reasons of a type)
 * }} props
 */
export default function FieldInput({ id, field, value, onChange, disabled = false, users = null, choices = null }) {
  const options = choices ?? field.options?.choices ?? []
  switch (field.type) {
    case 'long_text':
    case 'json':
      return (
        <textarea
          id={id}
          value={value ?? ''}
          rows={field.type === 'json' ? 5 : 4}
          disabled={disabled}
          spellCheck={field.type !== 'json'}
          onChange={(event) => onChange(event.target.value)}
          className={`${INPUT} resize-y ${field.type === 'json' ? 'font-mono text-xs' : ''}`}
        />
      )
    case 'bool':
      return (
        <select
          id={id}
          value={value ?? ''}
          disabled={disabled}
          onChange={(event) => onChange(event.target.value)}
          className={`${INPUT} cursor-pointer`}
        >
          <option value="">(not set)</option>
          <option value="true">yes</option>
          <option value="false">no</option>
        </select>
      )
    case 'choice':
      return (
        <select
          id={id}
          value={value ?? ''}
          disabled={disabled}
          onChange={(event) => onChange(event.target.value)}
          className={`${INPUT} cursor-pointer`}
        >
          <option value="">(not set)</option>
          {/* A value that is no longer among the choices is still shown, so that it is not lost by opening the form. */}
          {value && !options.includes(value) && <option value={value}>{value}</option>}
          {options.map((choice) => (
            <option key={choice} value={choice}>
              {choice}
            </option>
          ))}
        </select>
      )
    case 'multi_choice': {
      const chosen = Array.isArray(value) ? value : []
      return (
        <div id={id} role="group" aria-label={field.label} className="flex flex-wrap gap-x-4 gap-y-1">
          {options.map((choice) => (
            <label key={choice} className="flex items-center gap-1.5 text-sm text-fg">
              <input
                type="checkbox"
                checked={chosen.includes(choice)}
                disabled={disabled}
                onChange={(event) =>
                  onChange(event.target.checked ? [...chosen, choice] : chosen.filter((item) => item !== choice))
                }
                className="h-4 w-4 accent-accent"
              />
              {choice}
            </label>
          ))}
        </div>
      )
    }
    case 'user':
      if (users) {
        return (
          <select
            id={id}
            value={value ?? ''}
            disabled={disabled}
            onChange={(event) => onChange(event.target.value)}
            className={`${INPUT} cursor-pointer`}
          >
            <option value="">(nobody)</option>
            {value && !users.includes(value) && <option value={value}>{value}</option>}
            {users.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        )
      }
      break
    case 'date':
    case 'timer':
      return (
        <div className="flex items-center gap-2">
          <input
            id={id}
            type="datetime-local"
            value={value ?? ''}
            disabled={disabled}
            onChange={(event) => onChange(event.target.value)}
            className={`${INPUT} font-mono`}
          />
          <span className="shrink-0 font-mono text-xs text-fg-muted">UTC</span>
        </div>
      )
    case 'list':
      return <Rows id={id} field={field} value={value} onChange={onChange} disabled={disabled} />
    default:
      break
  }
  return (
    <input
      id={id}
      type={field.type === 'number' ? 'number' : field.type === 'url' ? 'url' : 'text'}
      step={field.type === 'number' ? 'any' : undefined}
      value={value ?? ''}
      disabled={disabled}
      autoComplete="off"
      spellCheck={false}
      placeholder={
        field.type === 'tags'
          ? 'one, two, three'
          : field.type === 'url'
            ? 'https://…'
            : field.type === 'indicator'
              ? 'evil.example, 185.220.101.47, a hash…'
              : ''
      }
      onChange={(event) => onChange(event.target.value)}
      className={`${INPUT} ${field.type === 'text' ? '' : 'font-mono'}`}
    />
  )
}
