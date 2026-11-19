import { useCallback, useEffect, useRef, useState } from 'react'
import { ChevronDown, ChevronRight, Download, PackageOpen, PackagePlus, RefreshCw, Trash2, Upload } from 'lucide-react'
import { api, apiUrl, postForBlob, upload } from '../../../services/api.js'
import { saveBlob } from '../../../lib/download.js'
import { formatRelative } from '../../../lib/time.js'
import { useAuth } from '../../../context/AuthContext.jsx'
import {
  SOURCES,
  actionBadge,
  byKind,
  byVendor,
  cardCounts,
  choicesOf,
  contentsLine,
  diffLines,
  filterCards,
  idFromName,
  importable,
  initialSkips,
  itemKey,
  packCards,
  packProblem,
  planSummary,
  plural,
  uninstallCounts,
} from '../../../domain/packs.js'
import { Badge, Button, Modal, SearchInput } from '../../ui/index.js'

/*
 * Automation → Content packs (who manages content).
 *
 * What Nik is taught about a product, as one pack. The page is the catalogue:
 * the packs there are to install (read from a signed index, see
 * app/pack_catalogue.py) beside the ones that are installed, by vendor. A pack
 * of the catalogue or a file is inspected, shown item by item with what
 * applying it would do, and then applied, all of it or nothing; an installed
 * one is opened, updated or uninstalled; and a pack is made from items chosen
 * here, with what they need.
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
            ? 'Installing…'
            : can.changes
              ? `Install (${can.changes} ${can.changes === 1 ? 'change' : 'changes'})`
              : 'Install'}
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
    <section aria-label="Make a pack" className="space-y-4 border border-line p-4">
      <h3 className="text-sm font-semibold text-fg">Make a pack</h3>
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

/** The logo of a pack, or its initials where it has none (Nik ships no logo of a vendor it was not given). */
function PackLogo({ card }) {
  const [broken, setBroken] = useState(false)
  const path =
    card.logo === 'catalogue'
      ? `/packs/catalogue/${encodeURIComponent(card.id)}/logo`
      : card.logo === 'pack'
        ? `/packs/${encodeURIComponent(card.id)}/logo`
        : null
  const initials = card.name
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((word) => word[0].toUpperCase())
    .join('')
  return (
    <span
      aria-hidden="true"
      className="flex h-9 w-9 shrink-0 items-center justify-center border border-line bg-canvas font-mono text-xs text-fg-muted"
    >
      {path && !broken ? (
        <img src={apiUrl(path)} alt="" className="h-7 w-7 object-contain" onError={() => setBroken(true)} />
      ) : (
        initials || '?'
      )}
    </span>
  )
}

const STATE_BADGE = {
  installed: { color: 'emerald', label: 'installed' },
  update: { color: 'amber', label: 'update' },
  later: { color: 'slate', label: 'later Nik' },
}

/** One pack: what it is, what it holds, and what can be done with it here. */
function PackCard({ card, busy, onInstall, onOpen, onUninstall }) {
  const badge = STATE_BADGE[card.state]
  return (
    <li aria-label={card.name} className="flex flex-col gap-2 border border-line bg-panel p-3">
      <div className="flex items-start gap-2.5">
        <PackLogo card={card} />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold text-fg">{card.name}</p>
          <p className="truncate text-xs text-fg-muted">
            {[card.category, card.installed ? `${card.installed} installed` : card.version].filter(Boolean).join(' · ')}
          </p>
        </div>
        {badge && <Badge color={badge.color}>{card.state === 'update' ? `update ${card.version}` : badge.label}</Badge>}
      </div>
      <p className="text-xs text-fg-muted">{contentsLine(card.contents, card.premium)}</p>
      {card.needsNik && <p className="text-xs text-fg-muted">For Nik {card.needsNik} or later.</p>}
      <div className="mt-auto flex flex-wrap gap-2 pt-1">
        {card.state === 'available' && (
          <Button size="xs" disabled={busy} onClick={() => onInstall(card)}>
            Install…
          </Button>
        )}
        {card.state === 'update' && (
          <Button size="xs" disabled={busy} onClick={() => onInstall(card)}>
            See what changes…
          </Button>
        )}
        <Button size="xs" variant="secondary" onClick={() => onOpen(card)} aria-label={`Open ${card.name}`}>
          Open
        </Button>
        {card.installed && !card.builtin && (
          <Button
            size="xs"
            variant="ghost"
            icon={Trash2}
            onClick={() => onUninstall(card)}
            aria-label={`Uninstall ${card.name}`}
          >
            Uninstall…
          </Button>
        )}
      </div>
    </li>
  )
}

/** What a pack is and, when it is installed, each thing it gave and whether it is still as given. */
function PackDetails({ card, onClose, onDownload }) {
  const pack = card.pack
  return (
    <Modal
      open
      onClose={onClose}
      title={card.name}
      maxWidth="max-w-2xl"
      footer={
        <>
          {pack && (
            <Button variant="secondary" icon={Download} onClick={() => onDownload(pack)}>
              Download as a file
            </Button>
          )}
          <Button onClick={onClose}>Close</Button>
        </>
      }
    >
      <div className="space-y-3 text-sm">
        <p className="text-xs text-fg-muted">
          {[
            card.vendor !== 'Other' ? card.vendor : '',
            card.category,
            pack
              ? `${pack.version} installed, ${SOURCES[pack.source] ?? pack.source}`
              : `${card.version} in the catalogue`,
            pack?.updatedBy && !pack.builtin
              ? `by ${pack.updatedBy} on ${String(pack.updatedAt ?? '').slice(0, 10)}`
              : '',
          ]
            .filter(Boolean)
            .join(' · ')}
        </p>
        {card.description && <p className="text-fg">{card.description}</p>}
        {card.requires.length > 0 && (
          <p className="text-xs text-fg-muted">
            Requires: {card.requires.map((need) => `${need.pack} ${need.version}`).join(', ')}.
          </p>
        )}
        {!pack && <p className="text-xs text-fg-muted">It holds: {contentsLine(card.contents, card.premium)}.</p>}
        {pack && (
          <div className="grid gap-3 border border-line bg-sunken p-3 sm:grid-cols-2">
            {byKind(pack.items).map((group) => (
              <div key={group.kind}>
                <p className="mb-1 text-xs font-medium text-fg-muted">
                  {plural(group.label, group.items.length)} ({group.items.length})
                </p>
                <ul className="space-y-0.5 text-sm text-fg">
                  {group.items.map((item) => (
                    <li key={item.name} className="flex items-center gap-2">
                      <span className={item.there ? 'truncate' : 'truncate text-fg-muted line-through'}>
                        {item.name}
                      </span>
                      {!item.there && <span className="shrink-0 text-xs text-fg-muted">no longer here</span>}
                      {item.there && item.changed && <span className="shrink-0 text-xs text-med-fg">changed here</span>}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
            {pack.items.length === 0 && <p className="text-xs text-fg-muted">Nothing of it is listed.</p>}
          </div>
        )}
      </div>
    </Modal>
  )
}

/** Uninstalling: what would go and what would stay is shown first, and the instances are asked about. */
function UninstallDialog({ card, onClose, onDone }) {
  const [plan, setPlan] = useState(null)
  const [instances, setInstances] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const path = `/packs/${encodeURIComponent(card.id)}`
  useEffect(() => {
    let alive = true
    api.get(`${path}/uninstall?instances=${instances}`).then(
      (found) => alive && setPlan(found),
      (failure) => alive && setError(failure.message),
    )
    return () => {
      alive = false
    }
  }, [path, instances])
  const run = (query, said) => {
    setBusy(true)
    setError(null)
    api
      .del(`${path}${query}`)
      .then(
        (done) => onDone(said(done)),
        (failure) => setError(failure.message),
      )
      .finally(() => setBusy(false))
  }
  const counts = uninstallCounts(plan?.items)
  return (
    <Modal
      open
      onClose={onClose}
      title={`Uninstall ${card.name}`}
      maxWidth="max-w-2xl"
      footer={
        <>
          <Button
            variant="ghost"
            disabled={busy}
            title="The pack leaves the list; everything it gave stays"
            onClick={() => run('', () => `${card.name} is off the list. What it gave stays.`)}
          >
            Only take it off the list
          </Button>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="danger"
            disabled={busy || !plan}
            onClick={() =>
              run(`?remove=true&instances=${instances}`, (done) => {
                const kept = done?.kept?.length ?? 0
                return `${card.name} was uninstalled: ${done?.removed?.length ?? 0} removed${kept ? `, ${kept} kept` : ''}.`
              })
            }
          >
            {busy ? 'Uninstalling…' : 'Uninstall'}
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm">
        <p className="text-fg-muted">
          What the pack gave is removed. What was changed here, or is used by something else, stays and is no
          pack&apos;s any more.
        </p>
        {error && (
          <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-high-fg">
            {error}
          </p>
        )}
        {!plan && !error && (
          <p role="status" className="font-mono text-xs text-fg-muted">
            Loading…
          </p>
        )}
        {plan && (
          <>
            <p role="status" className="text-xs text-fg-muted">
              {counts.remove} to remove, {counts.keep} to keep{counts.gone ? `, ${counts.gone} no longer here` : ''}.
            </p>
            <ul aria-label="What uninstalling does" className="divide-y divide-line-soft border border-line">
              {plan.items.map((item) => (
                <li key={`${item.kind}/${item.name}`} className="flex flex-wrap items-center gap-2 px-3 py-1.5">
                  <span className="w-32 shrink-0 text-xs text-fg-muted">{item.label}</span>
                  <span className="min-w-0 flex-1 truncate text-fg">{item.name}</span>
                  {item.why && <span className="text-xs text-fg-muted">{item.why}</span>}
                  <Badge color={item.action === 'remove' ? 'red' : 'slate'}>{item.action}</Badge>
                </li>
              ))}
            </ul>
            {plan.instances > 0 && (
              <label className="flex items-start gap-2 text-fg">
                <input
                  type="checkbox"
                  checked={instances}
                  onChange={(event) => setInstances(event.target.checked)}
                  className="mt-0.5 h-4 w-4 accent-[var(--color-accent)]"
                />
                <span>
                  Also delete {plan.instances === 1 ? 'its instance' : `its ${plan.instances} instances`}, with the
                  credentials {plan.instances === 1 ? 'it holds' : 'they hold'}
                  <span className="block text-xs text-fg-muted">
                    Without this a connector that has an instance stays, with its instance.
                  </span>
                </span>
              </label>
            )}
          </>
        )}
      </div>
    </Modal>
  )
}

/** Where the catalogue is read from (admin): another address, and the key what is there is signed with. */
function AddressDialog({ catalogue, onClose, onSaved }) {
  const [address, setAddress] = useState(catalogue.custom ? catalogue.address : '')
  const [key, setKey] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const save = (body) => {
    setBusy(true)
    setError(null)
    api
      .put('/packs/catalogue/address', body)
      .then(onSaved, (failure) => setError(failure.message))
      .finally(() => setBusy(false))
  }
  return (
    <Modal
      open
      onClose={onClose}
      title="Catalogue address"
      footer={
        <>
          {catalogue.custom && (
            <Button variant="ghost" disabled={busy} onClick={() => save({})}>
              Back to the catalogue of Nik
            </Button>
          )}
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button type="submit" form="form-catalogue" disabled={busy || !address.trim()}>
            Save
          </Button>
        </>
      }
    >
      <form
        id="form-catalogue"
        className="space-y-3 text-sm"
        onSubmit={(event) => {
          event.preventDefault()
          save({ address: address.trim(), key: key.trim() })
        }}
      >
        <p className="text-fg-muted">
          Nik reads the packs there are from an index and takes each pack from beside it. Set another address for a copy
          kept inside your network, or a catalogue of your own made with{' '}
          <span className="font-mono text-xs">python -m app.pack_build</span>.
        </p>
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-fg-muted">Address of index.json (https)</span>
          <input
            type="url"
            value={address}
            maxLength={500}
            placeholder="https://packs.example.com/nik/index.json"
            onChange={(event) => setAddress(event.target.value)}
            className={`${FIELD} font-mono`}
          />
        </label>
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-fg-muted">Public key it is signed with</span>
          <input
            type="text"
            value={key}
            maxLength={100}
            autoComplete="off"
            placeholder={catalogue.ownKey ? 'A key is set: leave empty to use the key of Nik' : 'Empty: the key of Nik'}
            onChange={(event) => setKey(event.target.value)}
            className={`${FIELD} font-mono`}
          />
          <span className="mt-1 block text-xs text-fg-muted">
            A copy of the catalogue of Nik keeps its signature: leave this empty. A catalogue of your own is signed with
            your key: paste its public half (base64).
          </span>
        </label>
        {error && (
          <p role="alert" className="text-high">
            {error}
          </p>
        )}
      </form>
    </Modal>
  )
}

const FILTERS = [
  { id: 'all', label: 'All' },
  { id: 'installed', label: 'Installed' },
  { id: 'updates', label: 'Updates' },
]

export default function ContentPacksSection() {
  const { can } = useAuth()
  const fileRef = useRef(null)
  const [packs, setPacks] = useState(null)
  const [catalogue, setCatalogue] = useState(null)
  const [show, setShow] = useState('all')
  const [query, setQuery] = useState('')
  const [plan, setPlan] = useState(null)
  const [exporting, setExporting] = useState(false)
  const [opened, setOpened] = useState(null) // the card in "Open"
  const [removing, setRemoving] = useState(null) // the card being uninstalled
  const [addressing, setAddressing] = useState(false)
  const [message, setMessage] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState('') // 'file', 'catalogue', or the id of the pack being taken

  const reload = useCallback(
    () =>
      Promise.all([api.get('/packs'), api.get('/packs/catalogue')]).then(
        ([installed, found]) => {
          setPacks(installed.packs)
          setCatalogue(found)
          return found
        },
        (failure) => setError(failure.message),
      ),
    [],
  )
  const readAgain = useCallback(() => {
    setBusy('catalogue')
    setError(null)
    return api
      .post('/packs/catalogue/refresh')
      .then(setCatalogue, (failure) => {
        setError(failure.message)
        return api.get('/packs/catalogue').then(setCatalogue, () => {})
      })
      .finally(() => setBusy(''))
  }, [])
  useEffect(() => {
    // The first time the page is opened the catalogue was never read: it is read then, once.
    reload().then((found) => {
      if (found && found.address && !found.read && !found.error) readAgain()
    })
  }, [reload, readAgain])

  const inspect = (event) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    setBusy('file')
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
      .finally(() => setBusy(''))
  }
  const take = (card) => {
    setBusy(card.id)
    setError(null)
    setMessage(null)
    api
      .post(`/packs/catalogue/${encodeURIComponent(card.id)}/inspect`)
      .then(setPlan, (failure) => setError(failure.message))
      .finally(() => setBusy(''))
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

  const cards = packCards(catalogue, packs)
  const counts = cardCounts(cards)
  const groups = byVendor(filterCards(cards, show, query))
  const loading = packs === null || catalogue === null

  return (
    <section className="space-y-4">
      <div>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <PackageOpen className="h-5 w-5 text-accent" aria-hidden="true" />
            <h2 className="text-base font-semibold text-fg">Content packs</h2>
          </div>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="secondary"
              icon={Upload}
              onClick={() => fileRef.current?.click()}
              disabled={busy === 'file'}
            >
              {busy === 'file' ? 'Reading…' : 'Upload a .nikpack…'}
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
              Make a pack…
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
          What Nik is taught about a product, in one pack: its connector, types of incident, dashboards, classifiers and
          mappers, playbooks and scripts. Installing a pack adds each of them to its own page of Settings. Choosing a
          pack changes nothing: it shows what installing it would do.
        </p>
      </div>

      {catalogue && (
        <div
          aria-label="The catalogue"
          role="group"
          className="flex flex-wrap items-center gap-x-3 gap-y-1 border border-line bg-panel px-3 py-2 text-sm"
        >
          <span
            aria-hidden="true"
            className={`h-2 w-2 shrink-0 ${catalogue.error ? 'bg-high-line' : catalogue.read ? 'bg-accent' : 'bg-fg-subtle'}`}
          />
          <span className="text-fg">Catalogue</span>
          <span className="min-w-0 truncate font-mono text-xs text-fg-muted" title={catalogue.address}>
            {catalogue.address.replace(/^https:\/\//, '')}
          </span>
          <span className="text-xs text-fg-muted">
            {!catalogue.address
              ? 'none is set: packs come as files'
              : catalogue.error
                ? 'could not be read'
                : catalogue.read
                  ? `read ${formatRelative(catalogue.fetchedAt)} · ${catalogue.packs.length} packs`
                  : 'not read yet'}
            {catalogue.custom ? ' · set here' : ''}
          </span>
          <span className="flex-1" />
          <Button
            size="xs"
            variant="secondary"
            icon={RefreshCw}
            onClick={readAgain}
            disabled={busy === 'catalogue' || !catalogue.address}
          >
            {busy === 'catalogue' ? 'Reading…' : 'Read again'}
          </Button>
          {can('admin') && (
            <Button size="xs" variant="secondary" onClick={() => setAddressing(true)}>
              Catalogue address…
            </Button>
          )}
        </div>
      )}

      <p
        role="status"
        className={message ? 'border border-accent-strong bg-accent-soft px-3 py-2 text-sm text-accent-fg' : 'sr-only'}
      >
        {message}
      </p>
      {error && (
        <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
          {error}
          {catalogue?.error && catalogue.read ? ' What is shown is what was read before.' : ''}
          {catalogue?.error && !catalogue.read ? ' A pack can still be uploaded as a file.' : ''}
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

      <div className="flex flex-wrap items-center gap-2">
        <div role="group" aria-label="Which packs" className="flex gap-2">
          {FILTERS.map((filter) => (
            <button
              key={filter.id}
              type="button"
              aria-pressed={show === filter.id}
              onClick={() => setShow(filter.id)}
              className={[
                'border px-3 py-1.5 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                show === filter.id ? 'border-accent text-accent-fg' : 'border-line bg-panel text-fg hover:bg-raised',
              ].join(' ')}
            >
              {filter.label} {counts[filter.id === 'all' ? 'all' : filter.id]}
            </button>
          ))}
        </div>
        <span className="flex-1" />
        <SearchInput value={query} onChange={setQuery} placeholder="Search the packs…" className="w-64 max-w-full" />
      </div>

      {loading && !error && (
        <p role="status" className="py-6 text-center font-mono text-sm text-fg-muted">
          Loading…
        </p>
      )}
      {!loading && groups.length === 0 && (
        <p className="border border-line px-3 py-6 text-center text-sm text-fg-muted">
          {query || show !== 'all' ? 'No pack matches.' : 'No pack yet.'}
        </p>
      )}
      {groups.map((group) => (
        <section key={group.vendor} aria-label={`Packs of ${group.vendor}`} className="space-y-2">
          <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">{group.vendor}</h3>
          <ul className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {group.cards.map((card) => (
              <PackCard
                key={card.id}
                card={card}
                busy={busy === card.id}
                onInstall={take}
                onOpen={setOpened}
                onUninstall={setRemoving}
              />
            ))}
          </ul>
        </section>
      ))}

      {opened && <PackDetails card={opened} onClose={() => setOpened(null)} onDownload={download} />}
      {removing && (
        <UninstallDialog
          card={removing}
          onClose={() => setRemoving(null)}
          onDone={(said) => {
            setRemoving(null)
            setMessage(said)
            reload()
          }}
        />
      )}
      {addressing && catalogue && (
        <AddressDialog
          catalogue={catalogue}
          onClose={() => setAddressing(false)}
          onSaved={(found) => {
            setAddressing(false)
            setCatalogue(found)
            setMessage('The address of the catalogue was saved. Read it again to see what is there.')
          }}
        />
      )}
    </section>
  )
}
