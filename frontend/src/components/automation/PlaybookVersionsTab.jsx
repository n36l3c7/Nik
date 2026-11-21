import { useEffect, useState } from 'react'
import { RotateCcw } from 'lucide-react'
import { useToast } from '../../context/ToastContext.jsx'
import { api } from '../../services/api.js'
import { formatDateTime } from '../../lib/time.js'
import { Badge, Button, EmptyState, Wait } from '../ui/index.js'

/*
 * The versions of a playbook, newest first. The current one is what runs.
 * Restoring an older one saves it again as a new version: history is never
 * rewritten, and the draft on the canvas is replaced by it.
 */

/**
 * @param {{ playbook: object, canEdit: boolean, onRestored: (detail: object) => void }} props
 */
export default function PlaybookVersionsTab({ playbook, canEdit, onRestored }) {
  const { showToast } = useToast()
  const [versions, setVersions] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(null)

  useEffect(() => {
    let alive = true
    api
      .get(`/automation/playbooks/${encodeURIComponent(playbook.id)}/versions`)
      .then((found) => alive && setVersions(found.versions))
      .catch((failure) => alive && setError(failure.message))
    return () => {
      alive = false
    }
  }, [playbook.id, playbook.version])

  const restore = async (number) => {
    setBusy(number)
    try {
      const found = await api.post(
        `/automation/playbooks/${encodeURIComponent(playbook.id)}/versions/${number}/restore`,
      )
      showToast({ message: `Version ${number} is back, as version ${found.version}.` })
      onRestored(found)
    } catch (failure) {
      showToast({ message: failure.message })
    } finally {
      setBusy(null)
    }
  }

  if (error) {
    return (
      <p role="alert" className="text-sm text-high-fg">
        {error}
      </p>
    )
  }
  if (!versions) {
    return <Wait>Loading the versions…</Wait>
  }
  if (versions.length === 0) {
    return (
      <EmptyState
        skull
        title="No version yet"
        message="The canvas edits a draft; “Save as version 1” checks it and makes it what runs."
      />
    )
  }
  return (
    <div className="overflow-x-auto border border-line">
      <table className="w-full min-w-[640px] border-collapse text-left font-mono text-xs">
        <caption className="sr-only">Versions of {playbook.name}</caption>
        <thead className="bg-panel text-fg-muted">
          <tr>
            {['Version', 'Saved', 'By', 'Nodes', 'Note', ''].map((heading, index) => (
              <th key={index} scope="col" className="border-b border-line px-3 py-1.5 font-normal">
                {heading || <span className="sr-only">Actions</span>}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {versions.map((version) => (
            <tr key={version.version}>
              <th scope="row" className="border-b border-line-soft px-3 py-2 font-normal text-fg">
                {version.version} {version.version === playbook.version && <Badge color="emerald">runs</Badge>}
              </th>
              <td className="border-b border-line-soft px-3 py-2 text-fg-muted">
                {formatDateTime(Date.parse(version.createdAt))}
              </td>
              <td className="border-b border-line-soft px-3 py-2 text-fg-muted">{version.createdBy}</td>
              <td className="border-b border-line-soft px-3 py-2 text-fg-muted">{version.nodes}</td>
              <td className="border-b border-line-soft px-3 py-2 font-sans text-fg-muted">{version.note}</td>
              <td className="border-b border-line-soft px-3 py-1 text-right">
                {canEdit && version.version !== playbook.version && (
                  <Button
                    variant="secondary"
                    size="xs"
                    icon={RotateCcw}
                    disabled={busy !== null}
                    aria-label={`Restore version ${version.version}`}
                    onClick={() => restore(version.version)}
                  >
                    Restore
                  </Button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
