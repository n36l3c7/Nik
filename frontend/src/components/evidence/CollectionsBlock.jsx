import { useCallback, useEffect, useState } from 'react'
import { Archive, FolderOpen, RefreshCw, Trash2 } from 'lucide-react'
import { Badge, Button } from '../ui/index.js'
import { collectionCounts, collectionState, isCollection, isWorking } from '../../domain/collections.js'
import { openCollection } from '../../lib/collectionDialog.js'
import { noteEvidenceChanged, useEvidenceSummary } from '../../lib/useEvidenceSummary.js'
import { evidence } from '../../services/api.js'

/*
 * The "Collections" block of the Evidence page: each triage zip of the incident with how many files it holds
 * and how many were imported, its state, and what can be done with it: open its list again, list it again,
 * remove it (the files already imported stay). It asks the server again while one is being listed or imported.
 */

const POLL_MS = 2000

export default function CollectionsBlock({ incident, canWrite }) {
  const [rows, setRows] = useState([])
  const [error, setError] = useState('')
  const { summary } = useEvidenceSummary(incident.id)
  const archived = Boolean(incident.archivedAt)

  const load = useCallback(
    async (signal, background = false) => {
      try {
        const { sources } = await evidence.sources(incident.id, { kind: 'collection', signal, background })
        if (!signal?.aborted) {
          setRows(sources.filter(isCollection))
          setError('')
        }
        return sources
      } catch (failure) {
        if (failure?.name !== 'AbortError') setError(failure?.message || 'The collections could not be listed.')
        return null
      }
    },
    [incident.id],
  )
  const working = rows.some(isWorking)
  useEffect(() => {
    const controller = new AbortController()
    load(controller.signal)
    return () => controller.abort()
  }, [load, summary])
  useEffect(() => {
    if (!working) return undefined
    const controller = new AbortController()
    const timer = setTimeout(() => load(controller.signal, true), POLL_MS)
    return () => {
      clearTimeout(timer)
      controller.abort()
    }
  }, [working, rows, load])

  const act = async (work) => {
    try {
      await work()
      noteEvidenceChanged(incident.id)
      await load()
    } catch (failure) {
      setError(failure?.message || 'It could not be done.')
    }
  }

  if (rows.length === 0 && !error) return null
  return (
    <section aria-label="Collections" className="mb-4 border border-line bg-panel">
      <header className="flex items-center gap-2 border-b border-line px-4 py-2.5">
        <Archive className="h-4 w-4 text-fg-muted" aria-hidden="true" />
        <h3 className="text-sm font-semibold">Collections</h3>
      </header>
      {error && (
        <p role="alert" className="border-b border-high-line bg-high-soft px-4 py-2 text-sm text-high-fg">
          {error}
        </p>
      )}
      <ul className="divide-y divide-line-soft">
        {rows.map((row) => {
          const { found, imported } = collectionCounts(row)
          return (
            <li key={row.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2 text-[13px]">
              <span className="min-w-0 max-w-80 truncate font-mono" title={row.fileName}>
                {row.fileName}
              </span>
              <span className="font-mono text-xs text-fg-muted">
                {found === null ? '—' : found.toLocaleString('en-US')} files found · {imported.toLocaleString('en-US')}{' '}
                imported
              </span>
              <Badge color={row.state === 'failed' ? 'red' : isWorking(row) ? 'cyan' : 'slate'} title={row.error || ''}>
                {collectionState(row)}
                {row.work?.progress ? ` · ${row.work.progress}` : ''}
              </Badge>
              <span className="ml-auto flex flex-wrap items-center gap-1">
                <Button
                  variant="secondary"
                  size="xs"
                  icon={FolderOpen}
                  onClick={() => openCollection(incident.id, row.id)}
                >
                  Open the list
                </Button>
                {canWrite && !archived && (
                  <>
                    <Button
                      variant="ghost"
                      size="xs"
                      icon={RefreshCw}
                      disabled={isWorking(row)}
                      onClick={() => act(() => evidence.readAgain(incident.id, row.id))}
                    >
                      List again
                    </Button>
                    <Button
                      variant="ghost"
                      size="xs"
                      icon={Trash2}
                      disabled={isWorking(row)}
                      title="Remove the collection; the files already imported from it stay"
                      onClick={() => act(() => evidence.remove(incident.id, row.id))}
                    >
                      Remove
                    </Button>
                  </>
                )}
              </span>
            </li>
          )
        })}
      </ul>
    </section>
  )
}
