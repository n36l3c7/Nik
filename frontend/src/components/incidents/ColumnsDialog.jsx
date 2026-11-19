import { ArrowDown, ArrowUp } from 'lucide-react'
import { moveColumn, toggleColumn } from '../../domain/incidentList.js'
import { Button, Modal } from '../ui/index.js'

/*
 * The columns of the incident list: those that are shown, in their order,
 * with the buttons that move them; then those that can be added. Each change
 * shows in the table at once, and is remembered for this person.
 */

function Move({ icon: Icon, label, disabled, onClick }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      disabled={disabled}
      onClick={onClick}
      className="p-1 text-fg-muted hover:bg-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-30"
    >
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
    </button>
  )
}

/**
 * @param {{
 *   columns: object[],                 // every column there is (domain/incidentList.js)
 *   chosen: string[],                  // the keys shown, in order
 *   onChange: (keys: string[]) => void,
 *   onReset: () => void,               // back to the default columns
 *   onClose: () => void,
 * }} props
 */
export default function ColumnsDialog({ columns, chosen, onChange, onReset, onClose }) {
  const byKey = Object.fromEntries(columns.map((column) => [column.key, column]))
  const shown = chosen.map((key) => byKey[key]).filter(Boolean)
  const hidden = columns.filter((column) => !chosen.includes(column.key))
  const nameOf = (column) => column.name ?? column.label

  const line = (column, index = null) => (
    <li key={column.key} className="flex items-center gap-2 py-1">
      <label className="flex min-w-0 flex-1 items-center gap-2">
        <input
          type="checkbox"
          checked={index !== null}
          // The last column stays: a table needs one.
          disabled={index !== null && shown.length === 1}
          onChange={() => onChange(toggleColumn(chosen, column.key))}
        />
        <span className="truncate text-fg">{nameOf(column)}</span>
        {column.field && <span className="shrink-0 font-mono text-[11px] text-fg-muted">{column.key}</span>}
      </label>
      {index !== null && (
        <span className="flex shrink-0">
          <Move
            icon={ArrowUp}
            label={`Move ${nameOf(column)} up`}
            disabled={index === 0}
            onClick={() => onChange(moveColumn(chosen, column.key, -1))}
          />
          <Move
            icon={ArrowDown}
            label={`Move ${nameOf(column)} down`}
            disabled={index === shown.length - 1}
            onClick={() => onChange(moveColumn(chosen, column.key, 1))}
          />
        </span>
      )}
    </li>
  )

  return (
    <Modal
      open
      onClose={onClose}
      title="Columns"
      footer={
        <>
          {/* Never greyed out: a saved filter may show the default columns while the person's own are others. */}
          <Button variant="secondary" onClick={onReset}>
            Back to the default columns
          </Button>
          <Button onClick={onClose}>Done</Button>
        </>
      }
    >
      <div className="flex flex-col gap-4 text-sm">
        <section aria-label="Columns shown">
          <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">Shown, in this order</h3>
          <ul className="divide-y divide-line-soft">{shown.map((column, index) => line(column, index))}</ul>
        </section>
        {hidden.length > 0 && (
          <section aria-label="Columns not shown">
            <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">Not shown</h3>
            <ul className="divide-y divide-line-soft">{hidden.map((column) => line(column))}</ul>
          </section>
        )}
        <p className="text-xs text-fg-muted">
          The fields of the registry that apply to incidents are columns too. The choice is remembered in this browser,
          and a saved filter keeps the columns it was saved with.
        </p>
      </div>
    </Modal>
  )
}
