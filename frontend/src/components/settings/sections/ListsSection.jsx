import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Download, FolderOpen, Plus, Save, Trash2, Upload, X } from 'lucide-react'
import { useObjectMenu } from '../../menu/useObjectMenu.js'
import { api, apiUrl } from '../../../services/api.js'
import { useSettings } from '../../../context/SettingsContext.jsx'
import { onLocationChange } from '../../../lib/location.js'
import { formatDateTime } from '../../../lib/time.js'
import {
  ITEM_TYPES,
  LIST_KINDS,
  countText,
  documentProblem,
  entriesToText,
  fileFormat,
  fromRows,
  kindLabel,
  listPath,
  matching,
  nameFromLabel,
  nameProblem,
  openFromSearch,
  textToEntries,
  toRows,
} from '../../../domain/lists.js'
import { Badge, Button, Modal, SearchInput } from '../../ui/index.js'

/*
 * Lists (who manages lists).
 *
 * Every list a feature or a playbook reads by its name: those Nik ships
 * (the IoC allowlist, your domains, the suspicious keywords, the business
 * hours…), yours, and the watch lists of the Indicators page, which are read
 * here and changed where indicators are. The table on the left, the list
 * that is chosen on the right: what it is, its items, where it is used, and
 * its file (export, import).
 */

const INPUT =
  'w-full border border-line bg-canvas px-2 py-1.5 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-60'
const LABEL = 'text-xs font-medium text-fg-muted'

function NewList({ lists, onClose, onMade }) {
  const [label, setLabel] = useState('')
  const [name, setName] = useState(null) // null: follows the label
  const [kind, setKind] = useState('values')
  const [itemType, setItemType] = useState('text')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const shownName = name ?? nameFromLabel(label)
  const problem = shownName ? nameProblem(shownName, lists) : null

  const make = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      onMade(await api.post('/lists', { name: shownName, label: label.trim(), kind, itemType }))
    } catch (failure) {
      setError(failure.message)
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="New list"
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button type="submit" form="new-list" size="sm" disabled={busy || !shownName || Boolean(problem)}>
            Create the list
          </Button>
        </>
      }
    >
      <form id="new-list" onSubmit={make} className="flex flex-col gap-3">
        <div className="flex flex-col gap-1">
          <label htmlFor="new-list-label" className={LABEL}>
            Label
          </label>
          <input
            id="new-list-label"
            type="text"
            value={label}
            maxLength={120}
            autoFocus
            autoComplete="off"
            onChange={(event) => setLabel(event.target.value)}
            className={INPUT}
          />
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="new-list-name" className={LABEL}>
            Name
          </label>
          <input
            id="new-list-name"
            type="text"
            value={shownName}
            maxLength={49}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => setName(event.target.value)}
            className={`${INPUT} font-mono`}
          />
          <span className="text-xs text-fg-subtle">
            {problem ?? 'What playbooks and features call it. It does not change once the list is made.'}
          </span>
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="new-list-kind" className={LABEL}>
            Kind
          </label>
          <select
            id="new-list-kind"
            value={kind}
            onChange={(event) => setKind(event.target.value)}
            className={`${INPUT} cursor-pointer`}
          >
            {['values', 'key_value', 'json'].map((id) => (
              <option key={id} value={id}>
                {LIST_KINDS[id].label}: {LIST_KINDS[id].hint}
              </option>
            ))}
          </select>
        </div>
        {kind !== 'json' && (
          <div className="flex flex-col gap-1">
            <label htmlFor="new-list-type" className={LABEL}>
              Its items are
            </label>
            <select
              id="new-list-type"
              value={itemType}
              onChange={(event) => setItemType(event.target.value)}
              className={`${INPUT} cursor-pointer`}
            >
              {ITEM_TYPES.map((type) => (
                <option key={type.id} value={type.id}>
                  {type.label}
                </option>
              ))}
            </select>
          </div>
        )}
        {error && (
          <p role="alert" className="text-sm text-high-fg">
            {error}
          </p>
        )}
      </form>
    </Modal>
  )
}

/** The items of a list of values: a box, one a line. */
function ValuesEditor({ list, disabled, onSave }) {
  const start = entriesToText(list.entries)
  const [draft, setDraft] = useState(start)
  useEffect(() => setDraft(start), [start])
  const entries = textToEntries(draft, list.entries)
  const dirty = entriesToText(entries) !== start
  return (
    <div className="flex flex-col gap-2">
      <label htmlFor="list-values" className={LABEL}>
        Items, one a line
      </label>
      <textarea
        id="list-values"
        value={draft}
        rows={14}
        spellCheck={false}
        disabled={disabled}
        onChange={(event) => setDraft(event.target.value)}
        className={`${INPUT} font-mono text-xs`}
      />
      {!disabled && (
        <div className="flex items-center gap-3">
          <Button size="sm" icon={Save} disabled={!dirty} onClick={() => onSave({ entries })}>
            Save the items
          </Button>
          <span className="text-xs text-fg-muted">
            {entries.length} item{entries.length === 1 ? '' : 's'}
          </span>
        </div>
      )}
    </div>
  )
}

/** The items of a key → value list: a row each, a cell for each column the list names. */
function RowsEditor({ list, disabled, onSave }) {
  const start = useMemo(() => toRows(list), [list])
  const [rows, setRows] = useState(start)
  useEffect(() => setRows(start), [start])
  const columns = list.columns ?? []
  const dirty = JSON.stringify(fromRows(list, rows)) !== JSON.stringify(fromRows(list, start))
  const change = (index, patch) => setRows(rows.map((row, at) => (at === index ? { ...row, ...patch } : row)))
  return (
    <div className="flex flex-col gap-2">
      <div className="overflow-x-auto border border-line">
        <table className="w-full border-collapse text-left text-sm">
          <caption className="sr-only">Items of {list.label}</caption>
          <thead className="bg-panel font-mono text-xs text-fg-muted">
            <tr>
              <th scope="col" className="border-b border-line px-2 py-1.5 font-normal">
                Key
              </th>
              {columns.length ? (
                columns.map((column) => (
                  <th key={column.name} scope="col" className="border-b border-line px-2 py-1.5 font-normal">
                    {column.label}
                  </th>
                ))
              ) : (
                <th scope="col" className="border-b border-line px-2 py-1.5 font-normal">
                  Value
                </th>
              )}
              <th scope="col" className="border-b border-line px-2 py-1.5">
                <span className="sr-only">Remove</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, index) => (
              <tr key={index}>
                <td className="border-b border-line-soft p-1">
                  <input
                    type="text"
                    aria-label={`Key, row ${index + 1}`}
                    value={row.key}
                    disabled={disabled}
                    onChange={(event) => change(index, { key: event.target.value })}
                    className={`${INPUT} font-mono text-xs`}
                  />
                </td>
                {columns.length ? (
                  columns.map((column) => (
                    <td key={column.name} className="border-b border-line-soft p-1">
                      {column.type === 'choice' ? (
                        <select
                          aria-label={`${column.label}, row ${index + 1}`}
                          value={row.cells[column.name] ?? ''}
                          disabled={disabled}
                          onChange={(event) =>
                            change(index, { cells: { ...row.cells, [column.name]: event.target.value } })
                          }
                          className={`${INPUT} cursor-pointer text-xs`}
                        >
                          <option value="" />
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
                          value={row.cells[column.name] ?? ''}
                          disabled={disabled}
                          onChange={(event) =>
                            change(index, { cells: { ...row.cells, [column.name]: event.target.value } })
                          }
                          className={`${INPUT} text-xs`}
                        />
                      )}
                    </td>
                  ))
                ) : (
                  <td className="border-b border-line-soft p-1">
                    <input
                      type="text"
                      aria-label={`Value, row ${index + 1}`}
                      value={row.value}
                      disabled={disabled}
                      placeholder="a text, or JSON"
                      onChange={(event) => change(index, { value: event.target.value })}
                      className={`${INPUT} font-mono text-xs`}
                    />
                  </td>
                )}
                <td className="border-b border-line-soft p-1">
                  {!disabled && (
                    <Button
                      variant="ghost"
                      size="xs"
                      icon={X}
                      aria-label={`Remove row ${index + 1}`}
                      onClick={() => setRows(rows.filter((_, at) => at !== index))}
                    />
                  )}
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={columns.length + 3} className="px-2 py-3 text-sm text-fg-muted">
                  No item yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {!disabled && (
        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            icon={Plus}
            onClick={() => setRows([...rows, { key: '', value: '', note: '', cells: {} }])}
          >
            Add a row
          </Button>
          <Button size="sm" icon={Save} disabled={!dirty} onClick={() => onSave({ entries: fromRows(list, rows) })}>
            Save the items
          </Button>
        </div>
      )}
    </div>
  )
}

/** A list that is one document: its JSON. */
function DocumentEditor({ list, disabled, onSave }) {
  const start = JSON.stringify(list.document ?? null, null, 2)
  const [draft, setDraft] = useState(start)
  useEffect(() => setDraft(start), [start])
  const problem = documentProblem(draft)
  return (
    <div className="flex flex-col gap-2">
      <label htmlFor="list-document" className={LABEL}>
        The document, as JSON
      </label>
      <textarea
        id="list-document"
        value={draft}
        rows={12}
        spellCheck={false}
        disabled={disabled}
        onChange={(event) => setDraft(event.target.value)}
        className={`${INPUT} font-mono text-xs`}
      />
      {problem && draft !== start && (
        <p role="alert" className="text-xs text-high-fg">
          {problem}
        </p>
      )}
      {!disabled && (
        <Button
          size="sm"
          icon={Save}
          className="self-start"
          disabled={draft === start || Boolean(problem)}
          onClick={() => onSave({ document: JSON.parse(draft) })}
        >
          Save the document
        </Button>
      )}
    </div>
  )
}

/** The list that is chosen: what it is, its items, where it is used, its file. */
function Detail({ name, onChanged, onDeleted }) {
  const { reload } = useSettings()
  const [list, setList] = useState(null)
  const [error, setError] = useState(null)
  const [said, setSaid] = useState(null)
  const fileInput = useRef(null)

  useEffect(() => {
    let cancelled = false
    setList(null)
    setError(null)
    setSaid(null)
    api.get(`/lists/${encodeURIComponent(name)}`).then(
      (found) => !cancelled && setList(found),
      (failure) => !cancelled && setError(failure.message),
    )
    return () => {
      cancelled = true
    }
  }, [name])

  /** Run a change, show what the list is after it, and tell the pages that read lists. */
  const apply = async (request, done) => {
    setError(null)
    setSaid(null)
    try {
      const next = await request()
      if (next) setList(next)
      setSaid(done)
      onChanged()
      reload()
    } catch (failure) {
      setError(failure.message)
    }
  }
  const path = `/lists/${encodeURIComponent(name)}`
  const saveItems = (body) => apply(() => api.put(`${path}/items`, body), 'Saved.')
  const importFile = async (file) => {
    const format = fileFormat(file.name)
    if (!format) {
      setError('A list is imported from a .csv, .txt or .json file')
      return
    }
    const text = await file.text()
    apply(() => api.post(`${path}/import`, { format, text }), `Imported from ${file.name}.`)
  }

  if (error && !list) {
    return (
      <p role="alert" className="text-sm text-high-fg">
        {error}
      </p>
    )
  }
  if (!list) {
    return (
      <p role="status" className="font-mono text-sm text-fg-muted">
        Loading the list…
      </p>
    )
  }
  const readOnly = Boolean(list.readOnly)
  return (
    <article aria-label={list.label} className="flex flex-col gap-4">
      <header className="flex flex-col gap-1">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="text-base font-semibold text-fg">{list.label}</h3>
          <Badge color="slate">{kindLabel(list.kind)}</Badge>
          {list.builtin && <Badge color="cyan">shipped with Nik</Badge>}
          {readOnly && <Badge color="amber">read here only</Badge>}
        </div>
        <p className="font-mono text-xs text-fg-subtle">{list.name}</p>
        {list.description && <p className="text-sm text-fg-muted">{list.description}</p>}
        <p className="text-xs text-fg-subtle">
          {countText(list)}
          {list.updatedAt ? ` · changed ${formatDateTime(Date.parse(list.updatedAt))}` : ''}
          {list.updatedBy ? ` by ${list.updatedBy}` : ''}
        </p>
      </header>

      <section aria-label="Where it is used" className="flex flex-col gap-1">
        <p className={LABEL}>Where it is used</p>
        {list.usedBy.length === 0 ? (
          <p className="text-sm text-fg-muted">Nothing reads this list yet.</p>
        ) : (
          <ul className="ml-5 list-disc text-sm text-fg">
            {list.usedBy.map((where) => (
              <li key={where}>{where}</li>
            ))}
          </ul>
        )}
        <p className="text-xs text-fg-subtle">
          In a playbook: the nodes <em>Read a list</em>, <em>Is it in a list?</em>, <em>Add to a list</em>, and{' '}
          <code className="font-mono">{`{{ value | in_list('${list.name}') }}`}</code>.
        </p>
      </section>

      {!readOnly && (
        <label className="flex items-center gap-2 text-sm text-fg">
          <input
            type="checkbox"
            checked={list.writableByAutomation}
            onChange={(event) =>
              apply(
                () => api.put(path, { writableByAutomation: event.target.checked }),
                event.target.checked ? 'Playbooks may write to it.' : 'Playbooks may not write to it.',
              )
            }
            className="h-4 w-4 accent-accent"
          />
          Playbooks may write to this list
        </label>
      )}

      {list.kind === 'json' ? (
        <DocumentEditor list={list} disabled={readOnly} onSave={saveItems} />
      ) : list.kind === 'key_value' ? (
        <RowsEditor list={list} disabled={readOnly} onSave={saveItems} />
      ) : (
        <ValuesEditor list={list} disabled={readOnly} onSave={saveItems} />
      )}

      {(error || said) && (
        <p role={error ? 'alert' : 'status'} className={`text-sm ${error ? 'text-high-fg' : 'text-fg-muted'}`}>
          {error || said}
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2 border-t border-line pt-3">
        <a
          href={apiUrl(`${path}/export?format=json`)}
          download={`${list.name}.json`}
          className="flex h-8 items-center gap-1.5 border border-line px-3 text-sm text-fg hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <Download className="h-4 w-4" aria-hidden="true" />
          Export JSON
        </a>
        {list.kind !== 'json' && (
          <a
            href={apiUrl(`${path}/export?format=csv`)}
            download={`${list.name}.csv`}
            className="flex h-8 items-center gap-1.5 border border-line px-3 text-sm text-fg hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <Download className="h-4 w-4" aria-hidden="true" />
            Export CSV
          </a>
        )}
        {!readOnly && (
          <>
            <input
              ref={fileInput}
              type="file"
              accept=".csv,.txt,.json"
              aria-label="A file to import into the list"
              className="sr-only"
              onChange={(event) => {
                const [file] = event.target.files
                event.target.value = ''
                if (file) importFile(file)
              }}
            />
            <Button variant="secondary" size="sm" icon={Upload} onClick={() => fileInput.current?.click()}>
              Import a file…
            </Button>
          </>
        )}
        {!readOnly && !list.builtin && (
          <Button
            variant="ghost"
            size="sm"
            icon={Trash2}
            onClick={async () => {
              setError(null)
              try {
                await api.del(path)
                onDeleted()
              } catch (failure) {
                setError(failure.message)
              }
            }}
          >
            Delete the list
          </Button>
        )}
      </div>
    </article>
  )
}

export default function ListsSection() {
  const [lists, setLists] = useState(null)
  const [error, setError] = useState(null)
  const [query, setQuery] = useState('')
  const [chosen, setChosen] = useState(() => openFromSearch(window.location.search))
  const [adding, setAdding] = useState(false)
  const menu = useObjectMenu()

  const load = useCallback(async () => {
    try {
      setLists((await api.get('/lists')).lists)
      setError(null)
    } catch (failure) {
      setError(failure.message)
    }
  }, [])
  useEffect(() => {
    load()
  }, [load])
  // "Open in Lists" from another section names the list in the address.
  useEffect(
    () =>
      onLocationChange(() => {
        const wanted = openFromSearch(window.location.search)
        if (wanted) setChosen(wanted)
      }),
    [],
  )
  const shown = useMemo(() => matching(lists, query), [lists, query])
  const open = chosen && lists?.some((list) => list.name === chosen) ? chosen : (lists?.[0]?.name ?? null)

  return (
    <div className="@container flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-3xl text-sm text-fg-muted">
          What features and playbooks read by a name. A feature reads the list its own section says, and another can be
          chosen there.
        </p>
        <Button size="sm" icon={Plus} onClick={() => setAdding(true)}>
          New list
        </Button>
      </div>
      {error && (
        <p role="alert" className="text-sm text-high-fg">
          {error}
        </p>
      )}
      <div className="grid gap-5 @5xl:grid-cols-[minmax(0,26rem)_minmax(0,1fr)]">
        <div className="flex flex-col gap-2">
          <SearchInput value={query} onChange={setQuery} placeholder="Find a list" />
          <div className="overflow-x-auto border border-line">
            <table className="w-full border-collapse text-left text-sm">
              <caption className="sr-only">Lists</caption>
              <thead className="bg-panel font-mono text-xs text-fg-muted">
                <tr>
                  {['List', 'Kind', 'Holds', 'Used by'].map((heading) => (
                    <th key={heading} scope="col" className="border-b border-line px-3 py-1.5 font-normal">
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(shown ?? []).map((list) => (
                  <tr
                    key={list.name}
                    className={list.name === open ? 'bg-accent-soft' : ''}
                    onContextMenu={(event) =>
                      menu(event, {
                        title: list.label,
                        actions: [{ label: 'Open', icon: FolderOpen, onSelect: () => setChosen(list.name) }],
                        link: listPath(list.name),
                        copy: [{ label: 'Copy the name', text: list.name }],
                      })
                    }
                  >
                    <th scope="row" className="border-b border-line-soft px-3 py-1.5 font-normal">
                      <button
                        type="button"
                        aria-current={list.name === open ? 'true' : undefined}
                        onClick={() => setChosen(list.name)}
                        className="text-left text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                      >
                        {list.label}
                      </button>
                      <span className="block font-mono text-[11px] text-fg-subtle">{list.name}</span>
                    </th>
                    <td className="border-b border-line-soft px-3 py-1.5 text-fg-muted">{kindLabel(list.kind)}</td>
                    <td className="border-b border-line-soft px-3 py-1.5 font-mono text-xs text-fg-muted">
                      {countText(list)}
                    </td>
                    <td className="border-b border-line-soft px-3 py-1.5 text-fg-muted">{list.usedBy.length || '—'}</td>
                  </tr>
                ))}
                {lists === null && (
                  <tr>
                    <td colSpan={4} className="px-3 py-3 font-mono text-sm text-fg-muted">
                      Loading the lists…
                    </td>
                  </tr>
                )}
                {lists !== null && shown.length === 0 && (
                  <tr>
                    <td colSpan={4} className="px-3 py-3 text-sm text-fg-muted">
                      No list by that name.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
        <div className="min-w-0">
          {open && (
            <Detail
              key={open}
              name={open}
              onChanged={load}
              onDeleted={() => {
                setChosen(null)
                load()
              }}
            />
          )}
        </div>
      </div>
      {adding && (
        <NewList
          lists={lists ?? []}
          onClose={() => setAdding(false)}
          onMade={(made) => {
            setAdding(false)
            setChosen(made.name)
            load()
          }}
        />
      )}
    </div>
  )
}
