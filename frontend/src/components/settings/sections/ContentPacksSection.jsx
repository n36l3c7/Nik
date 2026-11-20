import { useCallback, useEffect, useRef, useState } from 'react'
import {
  ChevronDown,
  ChevronRight,
  Download,
  PackageOpen,
  PackagePlus,
  RefreshCw,
  Search,
  Trash2,
  Upload,
  X,
} from 'lucide-react'
import { api, apiUrl, postForBlob, upload } from '../../../services/api.js'
import { saveBlob } from '../../../lib/download.js'
import { formatRelative } from '../../../lib/time.js'
import { useStoredBoolean } from '../../../lib/useStoredBoolean.js'
import { useAuth } from '../../../context/AuthContext.jsx'
import {
  BULK,
  SOURCES,
  actionBadge,
  bulkApplyBody,
  bulkCounts,
  bulkPlanBody,
  bulkPlanLine,
  bulkResultLine,
  bulkTitle,
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
  selectShown,
  selectable,
  selectionActions,
  tagCounts,
  toggled,
  uninstallCounts,
} from '../../../domain/packs.js'
import { useObjectMenu } from '../../menu/useObjectMenu.js'
import { Badge, Button, Modal } from '../../ui/index.js'
import { useUnsavedChanges } from '../../../lib/unsaved.js'

/*
 * Automation → Content packs (who manages content).
 *
 * What Nik is taught about a product, as one pack. The page is the catalogue:
 * the packs there are to install (read from a signed index, see
 * app/pack_catalogue.py) beside the ones that are installed, by vendor. A pack
 * of the catalogue or a file is inspected, shown item by item with what
 * applying it would do, and then applied, all of it or nothing; an installed
 * one is opened, updated or uninstalled (never while something of it is in
 * use: the dialog then says what holds it); and a pack is made from items
 * chosen here, with what they need.
 *
 * A pack is looked for from the search box, the tags and "Hide the installed
 * ones". Several can be ticked and installed, updated or uninstalled in one
 * go: the server says what would happen to each, in the order they would be
 * done, and then does each on its own (app/pack_bulk.py).
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
  // What was chosen to keep or leave out, where it differs from what the plan proposed.
  const [proposed] = useState(() => JSON.stringify(choicesOf(skipped)))
  const unsaved = useUnsavedChanges(JSON.stringify(choicesOf(skipped)) !== proposed, {
    what: 'The plan of the pack',
  })
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
        <Button variant="secondary" onClick={() => unsaved.leave(onCancel)} disabled={busy}>
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
  // A pack being described and filled: leaving the form, Cancel included, asks first.
  const unsaved = useUnsavedChanges(
    chosen.size > 0 || Boolean(form.id.trim() || form.name.trim() || form.description.trim() || form.author.trim()),
    { what: 'The pack being made', name: form.name },
  )
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
        <Button variant="secondary" onClick={() => unsaved.leave(onClose)}>
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
function PackCard({ card, busy, selected, onSelect, onInstall, onOpen, onUninstall }) {
  const badge = STATE_BADGE[card.state]
  const menu = useObjectMenu()
  const takes = card.state === 'available' || card.state === 'update'
  return (
    <li
      aria-label={card.name}
      className={`flex flex-col gap-2 border bg-panel p-3 ${selected ? 'border-accent' : 'border-line'}`}
      onContextMenu={(event) =>
        menu(event, {
          title: card.name,
          actions: [
            { label: 'Open', onSelect: () => onOpen(card) },
            takes && {
              label: card.state === 'update' ? 'See what changes…' : 'Install…',
              disabled: busy,
              title: busy ? 'It is being installed' : undefined,
              onSelect: () => onInstall(card),
            },
            selectable(card) && {
              label: selected ? 'Take it out of the selection' : 'Select',
              onSelect: () => onSelect(card),
            },
          ],
          copy: [
            { label: 'Copy the name', text: card.name },
            { label: 'Copy the version', text: card.installed || card.version },
          ],
          danger: card.installed && !card.builtin ? [{ label: 'Uninstall…', onSelect: () => onUninstall(card) }] : [],
        })
      }
    >
      <div className="flex items-start gap-2.5">
        {selectable(card) && (
          <input
            type="checkbox"
            checked={selected}
            onChange={() => onSelect(card)}
            aria-label={`Select ${card.name}`}
            className="mt-2.5 h-4 w-4 shrink-0 accent-[var(--color-accent)]"
          />
        )}
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
      {card.tags.length > 0 && (
        <p aria-label={`Tags of ${card.name}`} className="flex flex-wrap gap-1">
          {card.tags.map((tag) => (
            <span key={tag} className="border border-line-soft px-1.5 font-mono text-[11px] leading-4 text-fg-muted">
              {tag}
            </span>
          ))}
        </p>
      )}
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

/** What is in use of a pack, each thing with what to do about it first. */
function HeldList({ held, label }) {
  return (
    <ul aria-label={label} className="divide-y divide-line-soft border border-high-line">
      {held.map((entry, index) => (
        <li key={index} className="px-3 py-1.5">
          <p className="text-fg">{entry.what}</p>
          <p className="text-xs text-fg-muted">{entry.todo}</p>
        </li>
      ))}
    </ul>
  )
}

/**
 * Uninstalling: what would go and what would stay is shown first. A pack of which something is in use is
 * not uninstalled: the dialog lists what holds it, with what to do first, and offers no Uninstall.
 */
function UninstallDialog({ card, onClose, onDone }) {
  const [plan, setPlan] = useState(null)
  const [asked, setAsked] = useState(0) // raised to read the plan again
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const path = `/packs/${encodeURIComponent(card.id)}`
  useEffect(() => {
    let alive = true
    api.get(`${path}/uninstall`).then(
      (found) => alive && setPlan(found),
      (failure) => alive && setError(failure.message),
    )
    return () => {
      alive = false
    }
  }, [path, asked])
  const run = (query, said) => {
    setBusy(true)
    setError(null)
    api
      .del(`${path}${query}`)
      .then(
        (done) => onDone(said(done)),
        (failure) => {
          // Something began to use it since the dialog was opened: the server says what, and the plan is read again.
          const held = failure.data?.detail?.held
          if (held) setAsked((count) => count + 1)
          else setError(failure.message)
        },
      )
      .finally(() => setBusy(false))
  }
  const counts = uninstallCounts(plan?.items)
  const held = plan?.held ?? []
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
            {held.length ? 'Close' : 'Cancel'}
          </Button>
          {plan && held.length === 0 && (
            <Button
              variant="danger"
              disabled={busy}
              onClick={() =>
                run('?remove=true', (done) => {
                  const kept = done?.kept?.length ?? 0
                  return `${card.name} was uninstalled: ${done?.removed?.length ?? 0} removed${kept ? `, ${kept} kept` : ''}.`
                })
              }
            >
              {busy ? 'Uninstalling…' : 'Uninstall'}
            </Button>
          )}
        </>
      }
    >
      <div className="space-y-3 text-sm">
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
        {plan && held.length > 0 && (
          <>
            <p role="status" className="border border-high-line bg-high-soft px-3 py-2 text-high-fg">
              {card.name} is in use: it cannot be uninstalled yet.
            </p>
            <p className="text-fg-muted">
              Nothing is taken from under what uses it. Settle {held.length === 1 ? 'this' : 'each of these'} first,
              then uninstall it.
            </p>
            <HeldList held={held} label="What holds the pack" />
          </>
        )}
        {plan && held.length === 0 && (
          <>
            <p className="text-fg-muted">
              What the pack gave is removed. What was changed here stays, with what it needs, and is no pack&apos;s any
              more.
            </p>
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
          </>
        )}
      </div>
    </Modal>
  )
}

const BULK_INTRO = {
  install:
    'Each pack is taken from the catalogue and installed on its own, a pack after the ones it requires. One that fails does not undo the others.',
  update:
    'Each pack is taken from the catalogue and updated on its own, a pack after the ones it requires. One that fails does not undo the others.',
  uninstall:
    'Each pack is uninstalled on its own, a pack before the ones it requires. One that is in use is left as it is.',
}

/**
 * Several packs at once. The server says what would happen to each, in the order they would be done, and
 * which ones it leaves out and why; after the confirmation it does each on its own and says how each went.
 */
function BulkDialog({ action, cards, onClose }) {
  const [plan, setPlan] = useState(null)
  const [result, setResult] = useState(null)
  const [open, setOpen] = useState([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const asked = JSON.stringify(bulkPlanBody(action, cards))
  useEffect(() => {
    let alive = true
    api.post('/packs/bulk/plan', JSON.parse(asked)).then(
      (found) => alive && setPlan(found),
      (failure) => alive && setError(failure.message),
    )
    return () => {
      alive = false
    }
  }, [asked])
  const apply = () => {
    setBusy(true)
    setError(null)
    api
      .post('/packs/bulk/apply', bulkApplyBody(plan))
      .then(setResult, (failure) => setError(failure.message))
      .finally(() => setBusy(false))
  }
  const words = BULK[action]
  const lines = (result ?? plan)?.packs ?? []
  // What was left out of the plan was not sent: it is still shown beside what was done.
  const left = result ? plan.packs.filter((line) => !line.ok) : []
  const counts = bulkCounts(lines)
  const close = () => onClose(result ? bulkCounts(result.packs) : null)
  return (
    <Modal
      open
      onClose={busy ? undefined : close}
      title={bulkTitle(action, cards.length)}
      maxWidth="max-w-3xl"
      footer={
        result ? (
          <Button onClick={close}>Close</Button>
        ) : (
          <>
            <Button variant="secondary" onClick={close} disabled={busy}>
              Cancel
            </Button>
            <Button
              variant={action === 'uninstall' ? 'danger' : 'primary'}
              disabled={busy || !plan || counts.ok === 0}
              onClick={apply}
            >
              {busy ? words.doing : `${words.verb} (${counts.ok})`}
            </Button>
          </>
        )
      }
    >
      <div className="space-y-3 text-sm">
        <p className="text-fg-muted">{BULK_INTRO[action]}</p>
        {error && (
          <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-high-fg">
            {error}
          </p>
        )}
        {!plan && !error && (
          <p role="status" className="font-mono text-xs text-fg-muted">
            {action === 'uninstall' ? 'Loading…' : 'Taking the packs from the catalogue…'}
          </p>
        )}
        {plan && (
          <p role="status" className="text-xs text-fg-muted">
            {result
              ? `${counts.ok} ${words.done}, ${counts.left + left.length} not.`
              : `${counts.ok} to ${words.verb.toLowerCase()}, ${counts.left} left out.`}
          </p>
        )}
        {plan && (
          <ul aria-label="The packs" className="divide-y divide-line-soft border border-line">
            {[...lines, ...left].map((line) => {
              const shown = open.includes(line.id)
              const items = line.items ?? []
              return (
                <li key={line.id} aria-label={line.name} className="px-3 py-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      aria-expanded={shown}
                      aria-label={`What ${line.name} holds`}
                      disabled={!items.length}
                      onClick={() => setOpen((old) => toggled(old, line.id))}
                      className="text-fg-muted hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-40"
                    >
                      {shown ? (
                        <ChevronDown className="h-4 w-4" aria-hidden="true" />
                      ) : (
                        <ChevronRight className="h-4 w-4" aria-hidden="true" />
                      )}
                    </button>
                    <span className="min-w-0 truncate font-medium text-fg">{line.name}</span>
                    <span className="font-mono text-xs text-fg-muted">{line.version}</span>
                    <span className="min-w-0 flex-1 text-xs text-fg-muted">
                      {result && lines.includes(line) ? bulkResultLine(action, line) : bulkPlanLine(action, line)}
                    </span>
                    {result && lines.includes(line) ? (
                      <Badge color={line.ok ? 'emerald' : 'red'}>{line.ok ? words.done : 'failed'}</Badge>
                    ) : (
                      !line.ok && <Badge color={line.held?.length ? 'amber' : 'red'}>left out</Badge>
                    )}
                  </div>
                  {!line.ok && !line.held?.length && <p className="mt-1 pl-6 text-xs text-high-fg">{line.why}</p>}
                  {!line.ok && line.held?.length > 0 && (
                    <div className="mt-1 space-y-1 pl-6">
                      <p className="text-xs text-high-fg">It is in use, and stays as it is:</p>
                      <HeldList held={line.held} label={`What holds ${line.name}`} />
                    </div>
                  )}
                  {shown && (
                    <ul aria-label={`The items of ${line.name}`} className="mt-2 space-y-0.5 pl-6">
                      {items.map((item) => {
                        const badge = action === 'uninstall' ? null : actionBadge(item.action)
                        return (
                          <li key={itemKey(item)} className="flex flex-wrap items-center gap-2">
                            <span className="w-32 shrink-0 text-xs text-fg-muted">{item.label}</span>
                            <span className="min-w-0 flex-1 truncate text-fg">{item.name}</span>
                            {item.why && <span className="text-xs text-fg-muted">{item.why}</span>}
                            {badge ? (
                              <Badge color={badge.color} title={badge.hint}>
                                {badge.label}
                              </Badge>
                            ) : (
                              <Badge color={item.action === 'remove' ? 'red' : 'slate'}>{item.action}</Badge>
                            )}
                          </li>
                        )
                      })}
                    </ul>
                  )}
                </li>
              )
            })}
          </ul>
        )}
        {plan && !result && action !== 'uninstall' && (
          <p className="text-xs text-fg-muted">
            To read what changes line by line, or to leave an item out, install a pack on its own.
          </p>
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
  const unsaved = useUnsavedChanges(
    address.trim() !== (catalogue.custom ? catalogue.address : '') || Boolean(key.trim()),
    { what: 'The address of the catalogue' },
  )
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
      onClose={() => unsaved.leave(onClose)}
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

/** The box a pack is looked for from: the first thing on the page, as wide as it. */
function PackSearch({ value, onChange }) {
  return (
    <div className="relative">
      <Search
        className="pointer-events-none absolute left-3.5 top-1/2 h-5 w-5 -translate-y-1/2 text-fg-muted"
        aria-hidden="true"
      />
      <input
        type="search"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder="Search the packs: a name, a vendor, a tag, a connector…"
        aria-label="Search the packs"
        className={[
          'h-12 w-full border border-line bg-canvas pl-11 pr-10 text-base text-fg placeholder:text-fg-muted',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
          '[&::-webkit-search-cancel-button]:hidden',
        ].join(' ')}
      />
      {value && (
        <button
          type="button"
          onClick={() => onChange('')}
          aria-label="Clear the search"
          className="absolute right-3 top-1/2 -translate-y-1/2 p-0.5 text-fg-muted hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>
      )}
    </div>
  )
}

export default function ContentPacksSection() {
  const { can } = useAuth()
  const fileRef = useRef(null)
  const [packs, setPacks] = useState(null)
  const [catalogue, setCatalogue] = useState(null)
  const [show, setShow] = useState('all')
  const [query, setQuery] = useState('')
  const [tags, setTags] = useState([])
  // The one thing the page keeps for the person, in this browser: whoever looks for something to install
  // does not want to see again what is installed.
  const [hideInstalled, setHideInstalled] = useStoredBoolean('nik.packs.hide-installed', false)
  const [selected, setSelected] = useState([]) // the ids of the packs that are ticked
  const [bulk, setBulk] = useState(null) // { action, cards }: what is being done to several
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
  const shown = filterCards(cards, show, query, { tags, hideInstalled })
  const groups = byVendor(shown)
  const offered = tagCounts(shown, tags)
  const chosen = selectionActions(cards, selected)
  const narrowed = Boolean(query || tags.length || show !== 'all' || hideInstalled)
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

      <div role="search" aria-label="Find a pack" className="space-y-2">
        <PackSearch value={query} onChange={setQuery} />
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
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
                {filter.label} {counts[filter.id]}
              </button>
            ))}
          </div>
          <label
            className={`flex items-center gap-2 text-sm ${show === 'all' ? 'text-fg' : 'text-fg-muted'}`}
            title={show === 'all' ? undefined : 'It applies to All: the other two show installed packs'}
          >
            <input
              type="checkbox"
              checked={hideInstalled}
              disabled={show !== 'all'}
              onChange={(event) => setHideInstalled(event.target.checked)}
              className="h-4 w-4 accent-[var(--color-accent)]"
            />
            Hide the installed ones
          </label>
          <span className="flex-1" />
          <Button
            size="xs"
            variant="ghost"
            disabled={!shown.some(selectable)}
            onClick={() => setSelected((old) => selectShown(old, shown))}
          >
            Select all shown
          </Button>
          <Button size="xs" variant="ghost" disabled={!selected.length} onClick={() => setSelected([])}>
            Select none
          </Button>
        </div>
        {offered.length > 0 && (
          <div
            role="group"
            aria-label="Tags"
            title="A pack must have every tag that is chosen"
            className="flex flex-wrap items-center gap-1.5"
          >
            <span className="mr-1 font-mono text-[11px] uppercase tracking-wider text-fg-muted">Tags</span>
            {offered.map((entry) => (
              <button
                key={entry.tag}
                type="button"
                aria-pressed={entry.chosen}
                onClick={() => setTags((old) => toggled(old, entry.tag))}
                className={[
                  'border px-2 py-0.5 font-mono text-[11px] leading-5',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                  entry.chosen ? 'border-accent text-accent-fg' : 'border-line bg-panel text-fg-muted hover:bg-raised',
                ].join(' ')}
              >
                {entry.tag} {entry.count}
              </button>
            ))}
            {tags.length > 0 && (
              <Button size="xs" variant="ghost" onClick={() => setTags([])}>
                Clear the tags
              </Button>
            )}
          </div>
        )}
      </div>

      {chosen.chosen.length > 0 && (
        <div
          role="toolbar"
          aria-label="The packs that are selected"
          className="sticky top-0 z-10 flex flex-wrap items-center gap-2 border border-accent bg-panel px-3 py-2 text-sm"
        >
          <span className="text-fg">{chosen.chosen.length} selected</span>
          <span className="flex-1" />
          {['install', 'update', 'uninstall'].map((action) => (
            <Button
              key={action}
              size="sm"
              variant={action === 'uninstall' ? 'danger' : action === 'install' ? 'primary' : 'secondary'}
              disabled={!chosen[action].length}
              onClick={() => setBulk({ action, cards: chosen[action] })}
            >
              {BULK[action].verb} ({chosen[action].length})…
            </Button>
          ))}
        </div>
      )}

      {loading && !error && (
        <p role="status" className="py-6 text-center font-mono text-sm text-fg-muted">
          Loading…
        </p>
      )}
      {!loading && groups.length === 0 && (
        <p className="border border-line px-3 py-6 text-center text-sm text-fg-muted">
          {narrowed ? 'No pack matches.' : 'No pack yet.'}
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
                selected={selected.includes(card.id)}
                onSelect={(found) => setSelected((old) => toggled(old, found.id))}
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
      {bulk && (
        <BulkDialog
          action={bulk.action}
          cards={bulk.cards}
          onClose={(done) => {
            const words = BULK[bulk.action]
            setBulk(null)
            if (!done) return
            // The selection is spent: the dialog that just closed said how each pack went.
            setSelected([])
            setError(null)
            setMessage(
              `${done.ok} ${done.ok === 1 ? 'pack' : 'packs'} ${words.done}${done.left ? `, ${done.left} not` : ''}.`,
            )
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
