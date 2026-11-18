import { formatValue } from '../../domain/fields.js'
import { IocValue } from '../../context/IocLookupContext.jsx'

/*
 * The fields of a section as a list of "label: value". A table field is drawn
 * as its rows; an indicator opens what Nik knows of it; tags are chips; an
 * address is a link that is not followed by itself (it comes from evidence).
 */

function Value({ field, value }) {
  const empty = value === undefined || value === null || value === '' || (Array.isArray(value) && value.length === 0)
  if (empty) return <span className="text-fg-subtle">—</span>
  if (field.type === 'tags' || field.type === 'multi_choice') {
    return (
      <span className="flex flex-wrap gap-1">
        {value.map((item) => (
          <span key={item} className="border border-line bg-canvas px-1.5 py-0.5 font-mono text-[11px] text-fg">
            {item}
          </span>
        ))}
      </span>
    )
  }
  if (field.type === 'indicator' && value?.value) {
    return <IocValue type={value.type} value={value.value} className="break-all font-mono text-xs" />
  }
  if (field.type === 'list') {
    const columns = field.options?.columns ?? []
    return (
      <div className="overflow-x-auto border border-line">
        <table className="w-full border-collapse text-left text-xs">
          <thead className="bg-panel font-mono text-fg-muted">
            <tr>
              {columns.map((column) => (
                <th key={column.name} scope="col" className="border-b border-line px-2 py-1 font-normal">
                  {column.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {value.map((row, index) => (
              <tr key={index}>
                {columns.map((column) => (
                  <td key={column.name} className="border-b border-line-soft px-2 py-1 text-fg">
                    {formatValue(column, row[column.name]) || '—'}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )
  }
  if (field.type === 'long_text') return <span className="whitespace-pre-wrap break-words text-fg">{value}</span>
  if (field.type === 'json') {
    return (
      <pre className="overflow-x-auto bg-canvas p-2 font-mono text-[11px] text-fg">
        {JSON.stringify(value, null, 2)}
      </pre>
    )
  }
  return <span className="break-words text-fg">{formatValue(field, value)}</span>
}

/**
 * @param {{
 *   fields: object[],             // fields of the registry, in order
 *   values: object,               // name → value
 *   columns?: 1 | 2,
 *   dense?: boolean,              // the side panel: label above value
 *   className?: string,           // more classes for the list (its columns, in the panel)
 * }} props
 */
export default function FieldList({ fields, values, columns = 1, dense = false, className = '' }) {
  return (
    <dl className={`grid gap-x-6 gap-y-2 text-sm ${columns === 2 && !dense ? 'sm:grid-cols-2' : ''} ${className}`}>
      {fields.map((field) => (
        <div
          key={field.name}
          className={dense ? 'flex flex-col gap-0.5' : 'flex flex-col gap-0.5 sm:flex-row sm:gap-3'}
        >
          <dt
            className={`shrink-0 font-mono text-[11px] uppercase tracking-wider text-fg-muted ${dense ? '' : 'sm:w-36 sm:pt-0.5'}`}
          >
            {field.label}
          </dt>
          <dd className="min-w-0 flex-1">
            <Value field={field} value={values[field.name]} />
          </dd>
        </div>
      ))}
    </dl>
  )
}
