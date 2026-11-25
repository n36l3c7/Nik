import { useEffect, useRef, useState, useSyncExternalStore } from 'react'
import { Bug, Search } from 'lucide-react'
import { Badge, Button, Modal, Tabs, TransferBar, Wait } from '../ui/index.js'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useNavigation } from '../../context/NavigationContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { useCanWrite } from '../../lib/useCanWrite.js'
import {
  importBody,
  importPercent,
  importText,
  kindOptions,
  memberState,
  memberTabs,
  placeOf,
  toggleKind,
  whatOf,
  whoOf,
} from '../../domain/collections.js'
import { reasonRows } from '../../domain/sourceFiles.js'
import { sizeText } from '../../domain/transfers.js'
import { closeCollection, collectionOpen, subscribeCollection } from '../../lib/collectionDialog.js'
import { noteEvidenceChanged } from '../../lib/useEvidenceSummary.js'
import { collections, evidence } from '../../services/api.js'

/*
 * The dialog of a collection (a triage zip): while the worker lists it, a bar; then its members a page at a time
 * from the server, with the filters of the list (the tabs with their counts, a search, the kinds), what was left
 * out and why, the import of the ones picked or of all that are importable (with its progress), and the
 * programs, which are never evidence and go to Malware Analysis with "Analyse". Opened by lib/collectionDialog.js.
 */

const POLL_MS = 1500
const PAGE = 100

/** The collection the dialog is open on, or null. Drawn once by the app. */
export default function CollectionHost() {
  const open = useSyncExternalStore(subscribeCollection, collectionOpen)
  if (!open) return null
  return (
    <CollectionDialog
      key={`${open.incidentId}:${open.sourceId}`}
      incidentId={open.incidentId}
      sourceId={open.sourceId}
    />
  )
}

const CHECK = 'h-4 w-4 accent-accent'

function CollectionDialog({ incidentId, sourceId }) {
  const { showToast } = useToast()
  const { goTo } = useNavigation()
  const { attachSample, activeIncident } = useIncidents()
  const canWrite = useCanWrite(activeIncident?.id === incidentId ? activeIncident : null)
  const [status, setStatus] = useState('all')
  const [text, setText] = useState('')
  const [search, setSearch] = useState('')
  const [kinds, setKinds] = useState([])
  const [state, setState] = useState({ collection: null, members: [], next: null, total: 0, counts: {}, error: '' })
  const [loadingMore, setLoadingMore] = useState(false)
  const [picked, setPicked] = useState(() => new Set())
  const [problem, setProblem] = useState('') // a sentence the server refused with (409)
  const [busy, setBusy] = useState('') // 'import' | 'again' | 'analyse:<n>'
  const [tick, setTick] = useState(0)
  const previous = useRef('')

  // The search is sent after a pause.
  useEffect(() => {
    const timer = setTimeout(() => setSearch(text.trim()), 300)
    return () => clearTimeout(timer)
  }, [text])

  const kindKey = kinds.join(',')
  // The first page: the collection row (its state and counts) and the members the filters keep.
  useEffect(() => {
    const controller = new AbortController()
    collections
      .members(incidentId, sourceId, {
        status,
        kind: kinds,
        q: search,
        limit: PAGE,
        signal: controller.signal,
        background: tick > 0,
      })
      .then((answer) => setState({ ...answer, error: '' }))
      .catch((failure) => {
        if (failure?.name !== 'AbortError')
          setState((held) => ({ ...held, error: failure?.message || 'The collection could not be read.' }))
      })
    return () => controller.abort()
    // `kinds` is read through its key: a new array with the same names does not ask again.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incidentId, sourceId, status, kindKey, search, tick])

  const collection = state.collection
  const working = collection?.state === 'listing' || collection?.state === 'importing'
  // While the worker lists or imports, ask again; the end of an import tells the pages their counts changed.
  useEffect(() => {
    if (!working) {
      if (previous.current === 'importing') noteEvidenceChanged(incidentId)
      previous.current = collection?.state ?? ''
      return undefined
    }
    previous.current = collection.state
    const timer = setTimeout(() => setTick((n) => n + 1), POLL_MS)
    return () => clearTimeout(timer)
  }, [working, collection, incidentId])

  const loadMore = async () => {
    setLoadingMore(true)
    try {
      const answer = await collections.members(incidentId, sourceId, {
        status,
        kind: kinds,
        q: search,
        limit: PAGE,
        cursor: state.next,
      })
      setState((held) => ({ ...answer, members: [...held.members, ...answer.members], error: '' }))
    } catch (failure) {
      setState((held) => ({ ...held, error: failure?.message || 'The next files could not be read.' }))
    } finally {
      setLoadingMore(false)
    }
  }

  const counts = state.counts ?? {}
  const importing = collection?.members?.importing ?? null
  const importable = counts.importable ?? 0
  // The kinds ticked narrow "all importable" to those sections.
  const forKinds = kinds.length > 0 ? kinds.reduce((sum, kind) => sum + (counts.byKind?.[kind] ?? 0), 0) : importable
  const toImport = picked.size > 0 ? picked.size : forKinds

  const runImport = async () => {
    setBusy('import')
    setProblem('')
    try {
      await collections.importMembers(incidentId, sourceId, importBody([...picked], kinds))
      setPicked(new Set())
      setTick((n) => n + 1)
    } catch (failure) {
      setProblem(failure?.message || 'The files could not be imported.')
    } finally {
      setBusy('')
    }
  }
  const again = async () => {
    setBusy('again')
    setProblem('')
    try {
      await evidence.readAgain(incidentId, sourceId)
      setTick((n) => n + 1)
    } catch (failure) {
      setProblem(failure?.message || 'The collection could not be listed again.')
    } finally {
      setBusy('')
    }
  }
  const analyse = async (member) => {
    setBusy(`analyse:${member.n}`)
    setProblem('')
    try {
      const result = await collections.analyse(incidentId, sourceId, member.n)
      attachSample(incidentId, result.sample)
      showToast({ message: `${member.fileName} is in Malware Analysis.` })
      closeCollection()
      goTo('malware')
    } catch (failure) {
      setProblem(`${member.fileName}: ${failure?.message || 'It could not be analysed.'}`)
    } finally {
      setBusy('')
    }
  }

  const toggle = (n) =>
    setPicked((held) => {
      const next = new Set(held)
      if (next.has(n)) next.delete(n)
      else next.add(n)
      return next
    })
  const selectable = state.members.filter((member) => member.importable && !member.imported)
  const allOnPage = selectable.length > 0 && selectable.every((member) => picked.has(member.n))
  const togglePage = () =>
    setPicked((held) => {
      const next = new Set(held)
      for (const member of selectable) {
        if (allOnPage) next.delete(member.n)
        else next.add(member.n)
      }
      return next
    })

  const skipped = reasonRows(collection?.report)
  const info = collection?.members
  const listing = collection?.state === 'listing' || (!collection && !state.error)
  const failed = collection?.state === 'failed'
  const pages = Array.from(new Set(state.members.filter((member) => member.imported).map((member) => member.kind)))
    .map(placeOf)
    .filter(Boolean)

  const footer = (
    <>
      <Button variant="secondary" onClick={closeCollection}>
        Close
      </Button>
      {canWrite && collection && !listing && (
        <Button variant="ghost" onClick={again} disabled={busy !== '' || working}>
          List again
        </Button>
      )}
      {canWrite && collection && !listing && !failed && (
        <Button onClick={runImport} disabled={busy !== '' || working || toImport === 0}>
          {toImport === 1 ? 'Import 1 file' : `Import ${toImport.toLocaleString('en-US')} files`}
        </Button>
      )}
    </>
  )

  return (
    <Modal
      open
      onClose={closeCollection}
      title={`Collection: ${collection?.fileName ?? 'listing…'}`}
      maxWidth="max-w-6xl"
      tall
      footer={footer}
    >
      <div className="space-y-4">
        {state.error && (
          <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
            {state.error}
          </p>
        )}
        {problem && (
          <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
            {problem}
          </p>
        )}
        {listing && !state.error && (
          <div className="space-y-2" role="status">
            <Wait>Listing the files of the collection…</Wait>
            <TransferBar label="Listing the collection" percent={null} />
            {collection?.work?.progress && (
              <p className="font-mono text-xs text-fg-muted">{collection.work.progress}</p>
            )}
          </div>
        )}
        {failed && (
          <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
            {collection.error || 'The collection could not be listed.'}
          </p>
        )}

        {collection && !listing && !failed && (
          <>
            <p className="text-sm text-fg-muted">
              {(collection.inFile ?? 0).toLocaleString('en-US')} files in the zip
              {info?.bytes ? `, ${sizeText(info.bytes)} unpacked` : ''}
              {info?.password ? ' (it is encrypted: the files could not be read)' : ''}
              {info?.unlisted ? `, ${info.unlisted.toLocaleString('en-US')} not listed (over the limit)` : ''}
              {info?.stopped ? `. The list stopped: ${info.stopped}` : ''}.
            </p>

            {importing && (
              <div className="space-y-1.5 border border-line bg-canvas p-3" role="status">
                <p className="text-sm text-fg">Importing{importing.current ? ` ${importing.current}` : ''}…</p>
                <TransferBar label="Importing the files" percent={importPercent(importing)} />
                <p className="font-mono text-xs text-fg-muted">{importText(importing)}</p>
              </div>
            )}
            {!importing && collection.members?.importing === null && info?.imported > 0 && (
              <p className="flex flex-wrap items-center gap-2 text-sm text-fg-muted">
                {info.imported.toLocaleString('en-US')} imported from this collection.
                {pages.map((place) => (
                  <Button
                    key={place.tab + place.label}
                    variant="ghost"
                    size="xs"
                    onClick={() => {
                      closeCollection()
                      goTo(place.tab)
                    }}
                  >
                    Open {place.label}
                  </Button>
                ))}
              </p>
            )}
            {importing?.error && (
              <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
                {importing.error}
              </p>
            )}

            <Tabs
              variant="section"
              label="Files of the collection"
              idPrefix="collection"
              items={memberTabs(counts)}
              value={status}
              onChange={(id) => {
                setStatus(id)
                setPicked(new Set())
              }}
            />

            <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
              <label className="relative">
                <Search
                  className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-fg-muted"
                  aria-hidden="true"
                />
                <input
                  type="search"
                  value={text}
                  onChange={(event) => setText(event.target.value)}
                  placeholder="Search the paths…"
                  aria-label="Search the paths of the collection"
                  className="w-64 border border-line bg-canvas py-1.5 pl-7 pr-2 font-mono text-[13px] text-fg placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                />
              </label>
              <fieldset className="flex flex-wrap items-center gap-3">
                <legend className="sr-only">Sections to import</legend>
                {kindOptions(counts.byKind).map((option) => (
                  <label key={option.kind} className="inline-flex items-center gap-1.5 text-xs text-fg">
                    <input
                      type="checkbox"
                      className={CHECK}
                      checked={kinds.includes(option.kind)}
                      onChange={() => setKinds((held) => toggleKind(held, option.kind))}
                    />
                    {option.label}
                    <span className="font-mono text-fg-muted">{option.count}</span>
                  </label>
                ))}
              </fieldset>
            </div>

            <div className="max-h-[42vh] overflow-auto border border-line">
              <table className="w-full min-w-[44rem] text-left text-[13px]">
                <thead className="sticky top-0 bg-canvas">
                  <tr className="border-b border-line font-mono text-xs text-fg-muted">
                    <th scope="col" className="w-8 px-3 py-2 font-normal">
                      <input
                        type="checkbox"
                        className={CHECK}
                        aria-label="Pick every importable file on this page"
                        checked={allOnPage}
                        disabled={selectable.length === 0 || !canWrite}
                        onChange={togglePage}
                      />
                    </th>
                    <th scope="col" className="px-3 py-2 font-normal">
                      Path
                    </th>
                    <th scope="col" className="px-3 py-2 font-normal">
                      Section · source
                    </th>
                    <th scope="col" className="px-3 py-2 font-normal">
                      Host · user
                    </th>
                    <th scope="col" className="px-3 py-2 text-right font-normal">
                      Size
                    </th>
                    <th scope="col" className="px-3 py-2 font-normal">
                      State
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line-soft">
                  {state.members.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-6 text-center font-mono text-fg-muted">
                        No files match
                      </td>
                    </tr>
                  )}
                  {state.members.map((member) => {
                    const mine = memberState(member)
                    const pickable = member.importable && !member.imported
                    return (
                      <tr key={member.n} className="hover:bg-raised">
                        <td className="px-3 py-1.5">
                          <input
                            type="checkbox"
                            className={CHECK}
                            aria-label={`Pick ${member.path}`}
                            checked={picked.has(member.n)}
                            disabled={!pickable || !canWrite}
                            onChange={() => toggle(member.n)}
                          />
                        </td>
                        <td className="max-w-md break-all px-3 py-1.5 font-mono text-xs" title={member.path}>
                          {member.path}
                        </td>
                        <td className="px-3 py-1.5 text-xs">{whatOf(member) || '—'}</td>
                        <td className="px-3 py-1.5 font-mono text-xs">{whoOf(member) || '—'}</td>
                        <td className="whitespace-nowrap px-3 py-1.5 text-right font-mono text-xs tabular-nums">
                          {sizeText(member.size)}
                        </td>
                        <td className="whitespace-nowrap px-3 py-1.5">
                          <span className="inline-flex items-center gap-2">
                            <Badge color={mine.color} title={mine.title}>
                              {mine.label}
                            </Badge>
                            {member.executable && canWrite && (
                              <Button
                                variant="secondary"
                                size="xs"
                                icon={Bug}
                                disabled={busy !== ''}
                                onClick={() => analyse(member)}
                                title="Send this program to Malware Analysis"
                              >
                                Analyse
                              </Button>
                            )}
                          </span>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-fg-muted">
              <span>
                {state.members.length.toLocaleString('en-US')} of {(state.total ?? 0).toLocaleString('en-US')} shown
                {picked.size > 0 ? ` · ${picked.size.toLocaleString('en-US')} picked` : ''}
              </span>
              {state.next && (
                <Button variant="secondary" size="xs" onClick={loadMore} disabled={loadingMore}>
                  {loadingMore ? 'Loading…' : 'Show more'}
                </Button>
              )}
            </div>

            {skipped.length > 0 && (
              <section aria-label="What was left out" className="space-y-1.5">
                <h4 className="text-sm font-semibold">Left out, and why</h4>
                <ul className="divide-y divide-line-soft border border-line text-[13px]">
                  {skipped.map((row) => (
                    <li key={row.reason} className="flex flex-wrap items-baseline gap-x-3 px-3 py-1.5">
                      <span className="font-mono text-xs tabular-nums text-fg-muted">
                        {row.records.toLocaleString('en-US')}
                      </span>
                      <span className="min-w-0 flex-1 break-words">{row.reason}</span>
                      {row.detail && <span className="break-all font-mono text-xs text-fg-muted">{row.detail}</span>}
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </>
        )}
      </div>
    </Modal>
  )
}
