import { useCallback, useEffect, useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, Copy, RefreshCw } from 'lucide-react'
import { useAuth } from '../../../context/AuthContext.jsx'
import { useToast } from '../../../context/ToastContext.jsx'
import { api } from '../../../services/api.js'
import { automationPath } from '../../../domain/automationNav.js'
import {
  asExpression,
  asReference,
  openAtFirst,
  provenanceOf,
  rows as treeRows,
  runOf,
  shown,
  sourceLabel,
} from '../../../domain/context.js'
import { setPath } from '../../../lib/location.js'
import { formatDateTime } from '../../../lib/time.js'
import { Button, SearchInput } from '../../ui/index.js'

/*
 * ============================================================================
 * CONTEXT — what a playbook reads of this incident, as a tree
 * ============================================================================
 *
 * Two roots: `incident` (its fields, by the names of the registry) and
 * `context` (the entities of the common schema: File, Mail, Ticket…, and
 * `ext`, what a connector knows beyond them). Choosing a value shows, in the
 * line under the tree, its path as a playbook writes it (`{{ … }}`) and as
 * the command line does (`${…}`), each copied with a click, and who set it
 * last: Nik's own analysis, a connector, a person, a run (which opens).
 *
 * It is read here, never written: the context is filled by the analysis and
 * by what commands and scripts declare.
 */

/**
 * @param {{ incident: object }} props
 */
export default function ContextTab({ incident }) {
  const { can } = useAuth()
  const { showToast } = useToast()
  const [answer, setAnswer] = useState(null)
  const [error, setError] = useState(null)
  const [open, setOpen] = useState(new Set())
  const [query, setQuery] = useState('')
  const [chosen, setChosen] = useState(null)

  const load = useCallback(async () => {
    try {
      const found = await api.get(`/incidents/${encodeURIComponent(incident.id)}/context`)
      setAnswer(found)
      setError(null)
      return found
    } catch (failure) {
      // An incident not saved yet has no context.
      if (failure.status === 404) setAnswer({ incident: {}, context: {}, provenance: {}, schema: {} })
      else setError(failure.message)
      return null
    }
  }, [incident.id])
  useEffect(() => {
    setAnswer(null)
    setChosen(null)
    load().then((found) => found && setOpen(openAtFirst(found)))
  }, [load])

  const list = useMemo(() => (answer ? treeRows(answer, open, query) : []), [answer, open, query])
  const row = list.find((item) => item.id === chosen) ?? null
  const set = row && row.root === 'context' ? provenanceOf(answer, row.keys) : null

  if (!can('automation.run')) {
    return <p className="text-sm text-fg-muted">Your roles do not include running playbooks.</p>
  }

  const toggle = (id) => {
    const next = new Set(open)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    setOpen(next)
  }
  const copy = async (text) => {
    try {
      await navigator.clipboard.writeText(text)
      showToast({ message: 'Copied.' })
    } catch {
      showToast({ message: 'The browser refused to copy.' })
    }
  }
  const empty = answer && Object.keys(answer.context ?? {}).length === 0

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <div>
          <h2 className="text-base font-semibold text-fg">Context</h2>
          <p className="text-sm text-fg-muted">
            What a playbook reads of this incident: its fields, and what the analysis and commands found.
          </p>
        </div>
        <span className="flex-1" />
        <div className="w-64">
          <SearchInput value={query} onChange={setQuery} placeholder="Find a key or a value…" />
        </div>
        <Button variant="secondary" size="sm" icon={RefreshCw} onClick={load}>
          Refresh
        </Button>
      </div>
      {error && (
        <p role="alert" className="text-sm text-high-fg">
          {error}
        </p>
      )}
      {!answer && !error && (
        <p role="status" className="font-mono text-sm text-fg-muted">
          Loading the context…
        </p>
      )}
      {answer && (
        <>
          <ul
            role="tree"
            aria-label="Context of the incident"
            className="border border-line bg-panel py-1 font-mono text-xs"
          >
            {list.map((item) => (
              <li
                key={item.id}
                role="treeitem"
                aria-level={item.depth + 1}
                aria-expanded={item.leaf ? undefined : query ? true : open.has(item.id)}
                aria-selected={item.id === chosen}
              >
                <button
                  type="button"
                  onClick={() => {
                    setChosen(item.id)
                    if (!item.leaf && !query) toggle(item.id)
                  }}
                  style={{ paddingLeft: `${8 + item.depth * 16}px` }}
                  className={`flex w-full items-baseline gap-2 py-0.5 pr-3 text-left hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent ${item.id === chosen ? 'bg-raised' : ''}`}
                >
                  {item.leaf ? (
                    <span className="inline-block w-3.5 shrink-0" />
                  ) : query || open.has(item.id) ? (
                    <ChevronDown className="h-3.5 w-3.5 shrink-0 self-center text-fg-muted" aria-hidden="true" />
                  ) : (
                    <ChevronRight className="h-3.5 w-3.5 shrink-0 self-center text-fg-muted" aria-hidden="true" />
                  )}
                  <span className={item.depth === 0 ? 'font-semibold text-accent-fg' : 'text-fg-muted'}>
                    {item.label}
                  </span>
                  {item.leaf ? (
                    <span className="min-w-0 flex-1 truncate text-fg">{shown(item.value)}</span>
                  ) : (
                    <span className="text-fg-subtle">
                      {item.list ? `${item.count} item${item.count === 1 ? '' : 's'}` : `${item.count}`}
                    </span>
                  )}
                </button>
              </li>
            ))}
            {list.length === 0 && !(empty && !query) && <li className="px-3 py-2 text-fg-muted">Nothing matches.</li>}
          </ul>
          {empty && !query && (
            <p className="text-sm text-fg-muted">
              The context holds nothing yet. The files, e-mails and addresses analysed for this incident appear here,
              and so does what the commands of connectors and scripts find.
            </p>
          )}
          <div
            aria-live="polite"
            aria-label="The chosen value"
            className="flex min-h-[56px] flex-col gap-1.5 border border-line bg-panel px-3 py-2 text-xs"
          >
            {row ? (
              <>
                <div className="flex flex-wrap items-center gap-2">
                  <code className="break-all font-mono text-fg">{asExpression(row.id)}</code>
                  <Button variant="ghost" size="xs" icon={Copy} onClick={() => copy(asExpression(row.id))}>
                    Copy
                  </Button>
                  <code className="break-all font-mono text-fg-muted">{asReference(row.id)}</code>
                  <Button
                    variant="ghost"
                    size="xs"
                    icon={Copy}
                    aria-label="Copy for the command line"
                    onClick={() => copy(asReference(row.id))}
                  >
                    Copy
                  </Button>
                </div>
                <p className="text-fg-muted">
                  {row.root === 'incident' ? (
                    'A field of the incident: changed from its page, by a playbook, or by a command that says so.'
                  ) : set ? (
                    <>
                      Set by{' '}
                      {runOf(set.source) ? (
                        <button
                          type="button"
                          onClick={() => setPath(automationPath('runs', runOf(set.source)))}
                          className="text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                        >
                          a playbook run
                        </button>
                      ) : (
                        <span className="text-fg">{sourceLabel(set.source)}</span>
                      )}{' '}
                      on {formatDateTime(Date.parse(set.at))}.
                    </>
                  ) : (
                    'Choose an item of an entity to see who set it.'
                  )}
                </p>
              </>
            ) : (
              <p className="text-fg-muted">Choose a value to copy its path and see who set it.</p>
            )}
          </div>
        </>
      )}
    </div>
  )
}
