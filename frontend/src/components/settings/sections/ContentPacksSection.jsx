import { useCallback, useEffect, useRef, useState } from 'react'
import { ChevronDown, ChevronRight, Download, PackageOpen, PackagePlus, Trash2, Upload } from 'lucide-react'
import { api, apiUrl, postForBlob, upload } from '../../../services/api.js'
import { saveBlob } from '../../../lib/download.js'
import {
  actionBadge,
  byKind,
  choicesOf,
  diffLines,
  idFromName,
  importable,
  initialSkips,
  itemKey,
  packLine,
  packProblem,
  planSummary,
  plural,
} from '../../../domain/packs.js'
import { Badge, Button } from '../../ui/index.js'

/*
 * Automation → Content packs (who manages content).
 *
 * What Nik is taught, carried as one file. Three things happen here: the
 * packs that are installed are listed with what came from each; a pack file
 * is inspected, shown item by item with what applying it would do, and then
 * applied, all of it or nothing; and a pack is made from items chosen here,
 * with what they need.
 */

const FIELD =
  'h-8 w-full min-w-0 border border-line bg-canvas px-2 text-sm text-fg ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const DIFF_CLASS = {
  add: 'bg-accent-soft text-accent-fg',
  del: 'bg-high-soft text-high-fg',
  hunk: 'text-info',
  same: 'text-fg-muted',
}

/** A difference, line by line. The + and - that start a line say what it is, with or without colour. */
function Diff({ text }) {
  return (
    <pre className="max-h-72 overflow-auto border border-line bg-sunken p-2 font-mono text-xs leading-5">
      {diffLines(text).map((line, index) => (
        <span key={index} className={`block whitespace-pre-wrap break-all px-1 ${DIFF_CLASS[line.kind]}`}>
          {line.text || ' '}
        </span>
      ))}
    </pre>
  )
}

/** The plan of an import: each item with what would be done, kept or left out. */
function Plan({ plan, onDone, onCancel }) {
  const [skipped, setSkipped] = useState(() => initialSkips(plan))
  const [open, setOpen] = useState(() => new Set())
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const can = importable(plan, skipped)
  const flip = (set, key) => {
    const next = new Set(set)
    if (!next.delete(key)) next.add(key)
    return next
  }
  const apply = () => {
    setBusy(true)
    setError(null)
    api
      .post('/packs/import', { token: plan.token, choices: choicesOf(skipped) })
      .then(onDone, (failure) => setError(failure.message))
      .finally(() => setBusy(false))
  }
  return (
    <section aria-label={`What importing ${plan.pack.name} would do`} className="space-y-3 border border-line p-4">
      <div>
        <h3 className="text-sm font-semibold text-fg">
          {plan.pack.name} <span className="font-mono text-xs font-normal text-fg-muted">{plan.pack.version}</span>
        </h3>
        <p className="text-xs text-fg-muted">
          {plan.pack.author ? `By ${plan.pack.author}. ` : ''}
          {plan.installed ? `Version ${plan.installed} is installed. ` : 'Not installed yet. '}
          {planSummary(plan.counts)}.
        </p>
        {plan.pack.description && <p className="mt-1 text-sm text-fg">{plan.pack.description}</p>}
      </div>
      {plan.problems.map((problem) => (
        <p key={problem} role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
          {problem}
        </p>
      ))}
      <ul aria-label="The items of the pack" className="divide-y divide-line-soft border border-line">
        {plan.items.map((item) => {
          const key = itemKey(item)
          const badge = actionBadge(item.action)
          const kept = !skipped.has(key)
          const shown = open.has(key)
          return (
            <li key={key} className="px-3 py-2">
              <div className="flex flex-wrap items-center gap-2">
                <input
                  type="checkbox"
                  checked={kept}
                  onChange={() => setSkipped((old) => flip(old, key))}
                  aria-label={`Apply ${item.label.toLowerCase()} ${item.name}`}
                  className="h-4 w-4 accent-[var(--color-accent)]"
                />
                <span className="w-36 shrink-0 text-xs text-fg-muted">{item.label}</span>
                <span className={`min-w-0 flex-1 truncate text-sm ${kept ? 'text-fg' : 'text-fg-muted line-through'}`}>
                  {item.name}
                </span>
                {item.from && <span className="text-xs text-fg-muted">now of the pack {item.from}</span>}
                <Badge color={badge.color} title={badge.hint}>
                  {badge.label}
                </Badge>
                {item.diff && (
                  <button
                    type="button"
                    aria-expanded={shown}
                    onClick={() => setOpen((old) => flip(old, key))}
                    className="flex items-center gap-1 text-xs text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    {shown ? (
                      <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" />
                    ) : (
                      <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
                    )}
                    What changes
                  </button>
                )}
              </div>
              {item.why && <p className="mt-1 pl-6 text-xs text-high-fg">{item.why}</p>}
              {item.note && <p className="mt-1 pl-6 text-xs text-fg-muted">{item.note}</p>}
              {shown && (
                <div className="mt-2 pl-6">
                  <Diff text={item.diff} />
                </div>
              )}
            </li>
          )
        })}
      </ul>
      {error && (
        <p role="alert" className="text-sm text-high">
          {error}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <Button onClick={apply} disabled={!can.ok || busy}>
          {busy
            ? 'Importing…'
            : can.changes
              ? `Import (${can.changes} ${can.changes === 1 ? 'change' : 'changes'})`
              : 'Import'}
        </Button>
        <Button variant="secondary" onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
        <p className="text-xs text-fg-muted">
          {can.ok ? 'Everything that is ticked is applied together, or nothing is.' : can.why}
        </p>
      </div>
    </section>
  )
}

/** Making a pack: its identity, the items, and what they bring with them. */
function ExportForm({ onClose, onError }) {
  const [kinds, setKinds] = useState(null)
  const [chosen, setChosen] = useState(() => new Set())
  const [needed, setNeeded] = useState([])
  const [form, setForm] = useState({
    id: '',
    name: '',
    version: '1.0.0',
    description: '',
    author: '',
    listItems: false,
  })
  const [idTouched, setIdTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    api.get('/packs/items').then(
      (found) => setKinds(found.kinds),
      (failure) => onError(failure.message),
    )
  }, [onError])
  const items = [...chosen].map((key) => {
    const [kind, ...rest] = key.split('/')
    return { kind, name: rest.join('/') }
  })
  const asked = JSON.stringify(items)
  useEffect(() => {
    if (!chosen.size) {
      setNeeded([])
      return undefined
    }
    let cancelled = false
    api.post('/packs/dependencies', { items: JSON.parse(asked) }).then(
      (found) => !cancelled && setNeeded(found.items.filter((item) => !item.asked)),
      () => !cancelled && setNeeded([]),
    )
    return () => {
      cancelled = true
    }
    // The choice is its text: a new set with the same items asks nothing.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [asked])
  const problem = packProblem(form, chosen.size)
  const set = (patch) => setForm((old) => ({ ...old, ...patch }))
  const make = () => {
    setBusy(true)
    postForBlob('/packs/export', { ...form, items })
      .then(
        (blob) => {
          saveBlob(blob, `${form.id}-${form.version}.nikpack`)
          onClose()
        },
        (failure) => onError(failure.message),
      )
      .finally(() => setBusy(false))
  }
  return (
    <section aria-label="Export a pack" className="space-y-4 border border-line p-4">
      <h3 className="text-sm font-semibold text-fg">Export a pack</h3>
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-fg-muted">Name</span>
          <input
            type="text"
            maxLength={120}
            value={form.name}
            onChange={(event) =>
              set({ name: event.target.value, ...(idTouched ? {} : { id: idFromName(event.target.value) }) })
            }
            className={FIELD}
          />
        </label>
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-fg-muted">Id</span>
          <input
            type="text"
            maxLength={49}
            value={form.id}
            onChange={(event) => {
              setIdTouched(true)
              set({ id: event.target.value })
            }}
            className={`${FIELD} font-mono`}
          />
        </label>
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-fg-muted">Version</span>
          <input
            type="text"
            maxLength={20}
            value={form.version}
            onChange={(event) => set({ version: event.target.value })}
            className={`${FIELD} font-mono`}
          />
        </label>
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-fg-muted">Author</span>
          <input
            type="text"
            maxLength={200}
            value={form.author}
            onChange={(event) => set({ author: event.target.value })}
            className={FIELD}
          />
        </label>
        <label className="block sm:col-span-2">
          <span className="mb-1 block text-xs font-medium text-fg-muted">Description</span>
          <input
            type="text"
            maxLength={2000}
            value={form.description}
            onChange={(event) => set({ description: event.target.value })}
            className={FIELD}
          />
        </label>
      </div>
      {kinds === null ? (
        <p role="status" className="font-mono text-xs text-fg-muted">
          Loading…
        </p>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {kinds
            .filter((group) => group.items.length)
            .map((group) => (
              <fieldset key={group.kind} className="border border-line p-2">
                <legend className="px-1 text-xs font-medium text-fg-muted">{plural(group.label, 2)}</legend>
                <div className="max-h-40 space-y-1 overflow-y-auto">
                  {group.items.map((item) => {
                    const key = `${group.kind}/${item.name}`
                    return (
                      <label key={key} className="flex items-center gap-2 text-sm text-fg">
                        <input
                          type="checkbox"
                          checked={chosen.has(key)}
                          onChange={() =>
                            setChosen((old) => {
                              const next = new Set(old)
                              if (!next.delete(key)) next.add(key)
                              return next
                            })
                          }
                          className="h-4 w-4 accent-[var(--color-accent)]"
                        />
                        <span className="min-w-0 truncate" title={item.name}>
                          {item.label}
                        </span>
                        {item.builtin && <span className="text-xs text-fg-subtle">Nik</span>}
                      </label>
                    )
                  })}
                </div>
              </fieldset>
            ))}
        </div>
      )}
      {needed.length > 0 && (
        <p className="border border-line bg-sunken px-3 py-2 text-xs text-fg-muted">
          <span className="font-medium text-fg">Comes with them, because they need it: </span>
          {needed.map((item) => `${item.label.toLowerCase()} ${item.name}`).join(', ')}.
        </p>
      )}
      <label className="flex items-center gap-2 text-sm text-fg">
        <input
          type="checkbox"
          checked={form.listItems}
          onChange={(event) => set({ listItems: event.target.checked })}
          className="h-4 w-4 accent-[var(--color-accent)]"
        />
        Lists go with what they hold (otherwise only what they are)
      </label>
      <div className="flex flex-wrap items-center gap-2">
        <Button icon={Download} onClick={make} disabled={Boolean(problem) || busy}>
          {busy ? 'Exporting…' : 'Export'}
        </Button>
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
        <p className="text-xs text-fg-muted">
          {problem ?? 'Never an instance, a credential, or what a playbook may reach and send.'}
        </p>
      </div>
    </section>
  )
}

export default function ContentPacksSection() {
  const fileRef = useRef(null)
  const [packs, setPacks] = useState(null)
  const [open, setOpen] = useState(() => new Set())
  const [plan, setPlan] = useState(null)
  const [exporting, setExporting] = useState(false)
  const [message, setMessage] = useState(null)
  const [error, setError] = useState(null)
  const [reading, setReading] = useState(false)

  const reload = useCallback(
    () =>
      api.get('/packs').then(
        (found) => setPacks(found.packs),
        (failure) => setError(failure.message),
      ),
    [],
  )
  useEffect(() => {
    reload()
  }, [reload])

  const inspect = (event) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    setReading(true)
    setError(null)
    setMessage(null)
    upload('/packs/inspect', file)
      .then(
        (found) => {
          setPlan(found)
          setExporting(false)
        },
        (failure) => setError(failure.message),
      )
      .finally(() => setReading(false))
  }
  const download = (pack) =>
    fetch(apiUrl(`/packs/${encodeURIComponent(pack.id)}/download`), { credentials: 'include' })
      .then((response) =>
        response.ok ? response.blob() : Promise.reject(new Error(`Request failed (${response.status})`)),
      )
      .then(
        (blob) => saveBlob(blob, `${pack.id}-${pack.version}.nikpack`),
        (failure) => setError(failure.message),
      )
  const forget = (pack) =>
    api.del(`/packs/${encodeURIComponent(pack.id)}`).then(
      () => {
        setMessage(`${pack.name} is off the list. What it brought stays.`)
        reload()
      },
      (failure) => setError(failure.message),
    )

  return (
    <section className="space-y-5">
      <div>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <PackageOpen className="h-5 w-5 text-accent" aria-hidden="true" />
            <h2 className="text-base font-semibold text-fg">Content packs</h2>
            {packs && <Badge color="slate">{packs.length}</Badge>}
          </div>
          <div className="flex gap-2">
            <Button size="sm" icon={Upload} onClick={() => fileRef.current?.click()} disabled={reading}>
              {reading ? 'Reading…' : 'Import a pack'}
            </Button>
            <Button
              size="sm"
              variant="secondary"
              icon={PackagePlus}
              onClick={() => {
                setExporting(true)
                setPlan(null)
              }}
            >
              Export a pack
            </Button>
            <input
              ref={fileRef}
              type="file"
              accept=".nikpack,.zip,application/zip"
              onChange={inspect}
              className="hidden"
              aria-label="A pack file"
            />
          </div>
        </div>
        <p className="mt-1 text-sm text-fg-muted">
          What Nik is taught (connectors, playbooks and their scripts, types of incident and their fields, mappers,
          lists, dashboards) carried from one Nik to another as one <span className="font-mono">.nikpack</span> file.
          Choosing a file changes nothing: it shows what importing it would do.
        </p>
      </div>

      <p
        role="status"
        className={message ? 'border border-accent-strong bg-accent-soft px-3 py-2 text-sm text-accent-fg' : 'sr-only'}
      >
        {message}
      </p>
      {error && (
        <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
          {error}
        </p>
      )}

      {plan && (
        <Plan
          key={plan.token}
          plan={plan}
          onCancel={() => setPlan(null)}
          onDone={(done) => {
            setPlan(null)
            setMessage(
              `${done.pack.name} ${done.pack.version} is installed: ${done.added} added, ${done.updated} updated, ${done.skipped} left out.`,
            )
            reload()
          }}
        />
      )}
      {exporting && <ExportForm onClose={() => setExporting(false)} onError={setError} />}

      <ul aria-label="Installed packs" className="divide-y divide-line border border-line">
        {(packs ?? []).map((pack) => {
          const shown = open.has(pack.id)
          return (
            <li key={pack.id}>
              <div className="flex flex-wrap items-center gap-2 px-3 py-2.5">
                <button
                  type="button"
                  aria-expanded={shown}
                  aria-label={`${shown ? 'Hide' : 'Show'} what came from ${pack.name}`}
                  onClick={() =>
                    setOpen((old) => {
                      const next = new Set(old)
                      if (!next.delete(pack.id)) next.add(pack.id)
                      return next
                    })
                  }
                  className="p-1 text-fg-muted hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  {shown ? (
                    <ChevronDown className="h-4 w-4" aria-hidden="true" />
                  ) : (
                    <ChevronRight className="h-4 w-4" aria-hidden="true" />
                  )}
                </button>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium text-fg">
                    {pack.name} <span className="font-mono text-xs font-normal text-fg-muted">{pack.version}</span>
                  </p>
                  <p className="truncate text-xs text-fg-muted">
                    {packLine(pack)}
                    {pack.description ? ` · ${pack.description}` : ''}
                  </p>
                </div>
                {pack.builtin && <Badge color="slate">Nik</Badge>}
                <Button
                  size="xs"
                  variant="ghost"
                  icon={Download}
                  onClick={() => download(pack)}
                  aria-label={`Download ${pack.name}`}
                  title="Download as a file"
                />
                {!pack.builtin && (
                  <Button
                    size="xs"
                    variant="ghost"
                    icon={Trash2}
                    onClick={() => forget(pack)}
                    aria-label={`Take ${pack.name} off the list`}
                    title="Take off the list: what it brought stays"
                  />
                )}
              </div>
              {shown && (
                <div className="grid gap-3 border-t border-line-soft bg-sunken px-3 py-3 sm:grid-cols-2 xl:grid-cols-3">
                  {byKind(pack.items).map((group) => (
                    <div key={group.kind}>
                      <p className="mb-1 text-xs font-medium text-fg-muted">
                        {plural(group.label, group.items.length)} ({group.items.length})
                      </p>
                      <ul className="space-y-0.5 text-sm text-fg">
                        {group.items.map((item) => (
                          <li
                            key={item.name}
                            className={item.there ? 'truncate' : 'truncate text-fg-muted line-through'}
                            title={item.there ? item.name : 'No longer here'}
                          >
                            {item.name}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                  {pack.items.length === 0 && <p className="text-xs text-fg-muted">Nothing of it is listed.</p>}
                </div>
              )}
            </li>
          )
        })}
        {packs?.length === 0 && <li className="px-3 py-6 text-center text-sm text-fg-muted">No pack is installed.</li>}
        {packs === null && !error && (
          <li role="status" className="px-3 py-6 text-center font-mono text-sm text-fg-muted">
            Loading…
          </li>
        )}
      </ul>
    </section>
  )
}
