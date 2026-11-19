import { useState } from 'react'
import { Trash2 } from 'lucide-react'
import { groupFilters, nameProblem } from '../../domain/savedFilters.js'
import { Badge, Button, Modal } from '../ui/index.js'

/*
 * The two dialogs of the saved filters of the incident list: the one that
 * saves what is on screen under a name (or over the filter that is chosen),
 * and the one that renames, shares and deletes them.
 */

const INPUT =
  'h-8 w-full border border-line bg-canvas px-2.5 text-sm text-fg placeholder:text-fg-subtle ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/**
 * @param {{
 *   query: string,
 *   chosen: object | null,          // the filter that is chosen: one's own can be saved over
 *   filters: object[],
 *   onSave: (target: { id?: string, name?: string }) => Promise<void>,   // throws what the server refused
 *   onClose: () => void,
 * }} props
 */
export function SaveFilterDialog({ query, chosen, filters, onSave, onClose }) {
  const own = chosen?.mine ? chosen : null
  const [over, setOver] = useState(Boolean(own))
  const [name, setName] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  const submit = async (event) => {
    event.preventDefault()
    const problem = over ? null : nameProblem(name, filters)
    if (problem) {
      setError(problem)
      return
    }
    setBusy(true)
    setError(null)
    try {
      await onSave(over ? { id: own.id } : { name: name.trim() })
      onClose()
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="Save the filter"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="form-save-filter" disabled={busy}>
            Save the filter
          </Button>
        </>
      }
    >
      <form id="form-save-filter" onSubmit={submit} className="flex flex-col gap-4 text-sm">
        <div className="flex flex-col gap-1">
          <span className="text-fg-muted">The query on screen</span>
          <code className="break-words border border-line-soft bg-canvas px-2.5 py-1.5 font-mono text-xs text-fg">
            {query.trim() || 'no condition: every incident'}
          </code>
          <span className="text-xs text-fg-muted">
            The order of the rows and the columns on screen are saved with it.
          </span>
        </div>
        {own && (
          <fieldset className="flex flex-col gap-1.5">
            <legend className="mb-1 text-fg-muted">Where</legend>
            <label className="flex items-center gap-2">
              <input type="radio" name="save-filter-where" checked={over} onChange={() => setOver(true)} />
              <span>
                Over <strong className="font-semibold">{own.name}</strong>
                {own.shared ? ', which everyone sees' : ''}
              </span>
            </label>
            <label className="flex items-center gap-2">
              <input type="radio" name="save-filter-where" checked={!over} onChange={() => setOver(false)} />
              <span>As a new filter</span>
            </label>
          </fieldset>
        )}
        {!over && (
          <label className="flex flex-col gap-1" htmlFor="save-filter-name">
            <span className="text-fg-muted">Name</span>
            <input
              id="save-filter-name"
              type="text"
              autoFocus
              value={name}
              maxLength={80}
              onChange={(event) => setName(event.target.value)}
              placeholder="My open ones"
              autoComplete="off"
              className={INPUT}
            />
          </label>
        )}
        {error && (
          <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-high-fg">
            {error}
          </p>
        )}
      </form>
    </Modal>
  )
}

/** One filter of one's own: its name to change, and what can be done with it. */
function OwnRow({ filter, filters, isDefault, canShare, onRename, onShare, onDelete, onError }) {
  const [name, setName] = useState(filter.name)
  const [asking, setAsking] = useState(false)
  const changed = name.trim() !== filter.name

  const rename = async (event) => {
    event.preventDefault()
    if (!changed) return
    const problem = nameProblem(name, filters, filter.id)
    if (problem) {
      onError(problem)
      return
    }
    await onRename(filter.id, name.trim())
  }

  return (
    <li className="flex flex-wrap items-center gap-2 py-1.5">
      <form onSubmit={rename} className="flex min-w-0 flex-1 basis-48 items-center gap-2">
        <input
          type="text"
          aria-label={`Name of ${filter.name}`}
          value={name}
          maxLength={80}
          onChange={(event) => setName(event.target.value)}
          autoComplete="off"
          className={INPUT}
        />
        {changed && (
          <Button type="submit" size="sm" variant="secondary">
            Rename
          </Button>
        )}
      </form>
      {isDefault && <Badge color="emerald">default</Badge>}
      {filter.shared && !canShare && <Badge>shared</Badge>}
      {canShare && (
        <label className="flex shrink-0 items-center gap-1.5 text-xs text-fg-muted">
          <input
            type="checkbox"
            aria-label={`Share ${filter.name} with everyone`}
            checked={filter.shared}
            onChange={(event) => onShare(filter.id, event.target.checked)}
          />
          shared with everyone
        </label>
      )}
      {asking ? (
        <span className="flex shrink-0 items-center gap-1.5">
          <Button size="sm" variant="danger" onClick={() => onDelete(filter.id)}>
            Delete it
          </Button>
          <Button size="sm" variant="secondary" onClick={() => setAsking(false)}>
            Keep it
          </Button>
        </span>
      ) : (
        <Button
          size="sm"
          variant="ghost"
          icon={Trash2}
          aria-label={`Delete ${filter.name}`}
          title={filter.shared ? 'Delete it: everyone loses it' : 'Delete it'}
          onClick={() => setAsking(true)}
        />
      )}
    </li>
  )
}

/**
 * @param {{
 *   filters: object[], defaultId: string | null,
 *   canShare: boolean,                                 // an administrator
 *   onRename: (id: string, name: string) => Promise<void>,
 *   onShare: (id: string, shared: boolean) => Promise<void>,
 *   onDelete: (id: string) => Promise<void>,
 *   onClose: () => void,
 * }} props
 */
export function ManageFiltersDialog({ filters, defaultId, canShare, onRename, onShare, onDelete, onClose }) {
  const [error, setError] = useState(null)
  const { mine, shared } = groupFilters(filters)

  // What the server refuses is said here; the list is read again either way.
  const attempt =
    (action) =>
    async (...args) => {
      setError(null)
      try {
        await action(...args)
      } catch (failure) {
        setError(failure.message)
      }
    }

  return (
    <Modal
      open
      onClose={onClose}
      title="Manage the filters"
      maxWidth="max-w-2xl"
      footer={<Button onClick={onClose}>Done</Button>}
    >
      <div className="flex flex-col gap-4 text-sm">
        <section aria-label="My filters">
          <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">Mine</h3>
          {mine.length === 0 ? (
            <p className="py-2 text-fg-muted">Nothing here yet.</p>
          ) : (
            <ul className="divide-y divide-line-soft">
              {mine.map((filter) => (
                <OwnRow
                  key={`${filter.id}:${filter.name}`}
                  filter={filter}
                  filters={filters}
                  isDefault={filter.id === defaultId}
                  canShare={canShare}
                  onRename={attempt(onRename)}
                  onShare={attempt(onShare)}
                  onDelete={attempt(onDelete)}
                  onError={setError}
                />
              ))}
            </ul>
          )}
        </section>
        {shared.length > 0 && (
          <section aria-label="Filters shared with everyone">
            <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">Shared with everyone</h3>
            <ul className="divide-y divide-line-soft">
              {shared.map((filter) => (
                <li key={filter.id} className="flex flex-wrap items-center gap-2 py-1.5">
                  <span className="min-w-0 flex-1 truncate text-fg">{filter.name}</span>
                  <span className="text-xs text-fg-muted">by {filter.owner}</span>
                  {filter.id === defaultId && <Badge color="emerald">default</Badge>}
                  {canShare && (
                    <Button
                      size="sm"
                      variant="secondary"
                      aria-label={`Stop sharing ${filter.name}`}
                      onClick={() => attempt(onShare)(filter.id, false)}
                    >
                      Stop sharing
                    </Button>
                  )}
                </li>
              ))}
            </ul>
            <p className="pt-1 text-xs text-fg-muted">
              A filter of someone else is not changed here: choose it, then save it under a name of your own.
            </p>
          </section>
        )}
        {!canShare && <p className="text-xs text-fg-muted">An administrator shares a filter with everyone.</p>}
        {error && (
          <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-high-fg">
            {error}
          </p>
        )}
      </div>
    </Modal>
  )
}
