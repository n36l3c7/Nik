import { useEffect, useState } from 'react'
import { evidence } from '../../services/api.js'
import { formatDateTime } from '../../lib/time.js'
import { Button, Modal, Wait } from '../ui/index.js'

const ORDERS = [
  { id: 'rare', label: 'Rare first' },
  { id: 'common', label: 'Common first' },
]

/**
 * StackPanel: the values of one field of the records in view, with how many records hold each and when
 * they first and last were (the "stacking" of an investigation: the rare value is the one to look at).
 * Props: `incidentId`, `field` (a name of /stack: `host`, `username`, `channel`, `eventId`, `data.Key`...),
 * `label` (what the column is called on screen; the field when none), `filters` (the filters of the list
 * it was opened from), `onPick(value)` (a click on a value: the caller sets its filter and this closes),
 * `onClose`.
 */
export default function StackPanel({ incidentId, field, label = '', filters = {}, onPick, onClose }) {
  const [order, setOrder] = useState('rare')
  const [state, setState] = useState({ loading: true, error: '', answer: null })
  const filterKey = JSON.stringify(filters)

  useEffect(() => {
    const controller = new AbortController()
    setState({ loading: true, error: '', answer: null })
    evidence
      .stack(incidentId, { field, order, filters: JSON.parse(filterKey), signal: controller.signal })
      .then((answer) => setState({ loading: false, error: '', answer }))
      .catch((failure) => {
        if (failure?.name !== 'AbortError') {
          setState({ loading: false, error: failure?.message || 'The values could not be counted.', answer: null })
        }
      })
    return () => controller.abort()
  }, [incidentId, field, order, filterKey])

  const { loading, error, answer } = state
  const values = answer?.values ?? []

  return (
    <Modal
      open
      onClose={onClose}
      title={`Stack values: ${label || field}`}
      maxWidth="max-w-3xl"
      footer={
        <Button variant="secondary" onClick={onClose}>
          Close
        </Button>
      }
    >
      <div className="space-y-3">
        <div role="group" aria-label="Order" className="inline-flex border border-line bg-panel p-0.5">
          {ORDERS.map((item) => (
            <button
              key={item.id}
              type="button"
              aria-pressed={order === item.id}
              onClick={() => setOrder(item.id)}
              className={`px-3 py-1 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${order === item.id ? 'bg-accent-soft text-accent-fg' : 'text-fg-muted hover:text-fg'}`}
            >
              {item.label}
            </button>
          ))}
        </div>
        {loading && <Wait>Counting…</Wait>}
        {error && (
          <p role="alert" className="text-sm text-high">
            {error}
          </p>
        )}
        {answer && (
          <>
            <p className="text-xs text-fg-muted">
              {answer.distinct.toLocaleString('en-US')}
              {answer.distinctCapped ? '+' : ''} distinct values
              {answer.missing > 0 ? `, ${answer.missing.toLocaleString('en-US')} records without one` : ''}. Choose a
              value to filter on it.
            </p>
            <div className="max-h-[50vh] overflow-auto border border-line">
              <table className="w-full text-left text-xs">
                <thead className="sticky top-0 bg-panel text-fg-muted">
                  <tr className="border-b border-line">
                    <th className="px-3 py-1.5 font-medium">Value</th>
                    <th className="px-3 py-1.5 text-right font-medium">Records</th>
                    <th className="px-3 py-1.5 font-medium">First</th>
                    <th className="px-3 py-1.5 font-medium">Last</th>
                  </tr>
                </thead>
                <tbody>
                  {values.length === 0 && (
                    <tr>
                      <td colSpan={4} className="px-3 py-6 text-center font-mono text-fg-muted">
                        No values
                      </td>
                    </tr>
                  )}
                  {values.map((item) => (
                    <tr key={String(item.value)} className="border-b border-line-soft">
                      <td className="max-w-80 px-3 py-1.5 font-mono">
                        <button
                          type="button"
                          title={`Filter on ${item.value}`}
                          onClick={() => onPick(item.value)}
                          className="max-w-full truncate text-left text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                        >
                          {String(item.value)}
                        </button>
                      </td>
                      <td className="px-3 py-1.5 text-right font-mono tabular-nums">
                        {item.count.toLocaleString('en-US')}
                      </td>
                      <td className="whitespace-nowrap px-3 py-1.5 font-mono text-fg-muted">
                        {Number.isFinite(item.first) ? formatDateTime(item.first) : '—'}
                      </td>
                      <td className="whitespace-nowrap px-3 py-1.5 font-mono text-fg-muted">
                        {Number.isFinite(item.last) ? formatDateTime(item.last) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </Modal>
  )
}
