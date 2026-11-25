import { useCallback, useEffect, useMemo, useState } from 'react'
import { CircleHelp, Info } from 'lucide-react'
import { Button, Modal, Tabs } from '../../ui/index.js'
import SourceFiles from '../../evidence/SourceFiles.jsx'
import SourceViewer from '../../evidence/SourceViewer.jsx'
import CommandsSection from './CommandsSection.jsx'
import { useAuth } from '../../../context/AuthContext.jsx'
import { groupByShell } from '../../../domain/commands.js'
import { SHELLS, getShellById, shellsForOs } from '../../../config/shells.js'
import { getOsById, DEFAULT_OS } from '../../../config/os.js'
import { evidence } from '../../../services/api.js'

/*
 * "Command History" tab: one selector entry per shell (Bash, Zsh, Fish, PowerShell), the history files of
 * the shell (sent in parts and read by the worker), and the commands read from them. Which shells are
 * offered follows the incident's host OS, plus any shell that already has a file.
 *
 * The user and the host of a history file are not in the file: they are given here, before the file is
 * added, and kept with it (SourceFiles `uploadParams`).
 */

const ARCHIVED_NOTE = 'Archived: the records are not loaded. Take the incident out of the archive to read them again.'
const FIELD =
  'w-40 border border-line bg-canvas px-2 py-1.5 font-mono text-[13px] text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/** "Where to find these files": the path of the history of the shell on the host's OS, and what it keeps. */
function WhereToFind({ shell, os }) {
  const [open, setOpen] = useState(false)
  const source = shell.source
  const path = source.paths?.[os] ?? source.paths?.windows ?? source.paths?.linux ?? ''
  return (
    <>
      <Button variant="ghost" size="sm" icon={CircleHelp} onClick={() => setOpen(true)}>
        Where to find these files
      </Button>
      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title={`Where to find the ${shell.label} history (${getOsById(os)?.label ?? os})`}
        footer={
          <Button variant="secondary" onClick={() => setOpen(false)}>
            Close
          </Button>
        }
      >
        <div className="space-y-2 text-sm">
          <p className="text-xs text-fg-muted">
            <span className="font-medium">{source.label}:</span>{' '}
            <span className="break-all font-mono text-[11px]">{path}</span>
          </p>
          <p className="text-xs text-fg-muted">{source.hint}</p>
          <p className="flex items-start gap-1.5 text-xs text-fg-muted">
            <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            {shell.timestamps}
          </p>
        </div>
      </Modal>
    </>
  )
}

export default function CommandHistoryTab({ incident }) {
  const { can } = useAuth()
  const archived = Boolean(incident.archivedAt)
  const canWrite = can('write') && !archived
  const os = getOsById(incident.os) ? incident.os : DEFAULT_OS

  const [sources, setSources] = useState(null) // the files of the section, or null while they load
  const [version, setVersion] = useState(0) // bumped when a file was added, removed or read
  const [shellId, setShellId] = useState(null)
  const [user, setUser] = useState('')
  const [host, setHost] = useState('')
  const [wholeFile, setWholeFile] = useState(null)

  useEffect(() => {
    const controller = new AbortController()
    evidence
      .sources(incident.id, { kind: 'commands', signal: controller.signal, background: version > 0 })
      .then((answer) => setSources(answer.sources))
      .catch(() => setSources((held) => held ?? []))
    return () => controller.abort()
  }, [incident.id, version])

  const groups = useMemo(() => groupByShell(sources ?? []), [sources])

  // The shells of this host's OS, and any other that has a file.
  const visibleShells = useMemo(() => {
    const onOs = new Set(shellsForOs(os).map((item) => item.id))
    return SHELLS.filter((item) => onOs.has(item.id) || (groups[item.id]?.sources.length ?? 0) > 0)
  }, [os, groups])

  const active =
    getShellById(shellId) && visibleShells.some((item) => item.id === shellId)
      ? shellId
      : (visibleShells.find((item) => groups[item.id]?.count > 0)?.id ?? visibleShells[0]?.id ?? SHELLS[0].id)
  const shell = getShellById(active)
  const shellSources = groups[active]?.sources ?? []
  const readable = shellSources.filter((item) => item.state === 'done')
  const hasRecords = readable.length > 0 && !archived

  const items = visibleShells.map((item) => ({
    id: item.id,
    label: item.label,
    count: groups[item.id]?.count || undefined,
    partial: groups[item.id]?.partial,
  }))

  const changed = useCallback(() => setVersion((n) => n + 1), [])
  const ofShell = useCallback((item) => item.source === active, [active])
  const params = useMemo(() => ({ source: active, host: host.trim(), user: user.trim() }), [active, host, user])
  const expected = useMemo(
    () => [
      {
        key: active,
        label: shell.source.label,
        hint: shell.source.paths?.[os] ?? shell.source.paths?.windows ?? shell.source.paths?.linux ?? '',
      },
    ],
    [active, shell, os],
  )
  const match = useCallback((item) => (item.source === active ? active : null), [active])

  return (
    <div className="space-y-6">
      <Tabs variant="selector" label="Shell" items={items} value={active} onChange={setShellId} idPrefix="shell" />

      {archived && (
        <p role="status" className="border border-line bg-panel px-4 py-3 text-sm text-fg-muted">
          {ARCHIVED_NOTE}
        </p>
      )}

      {canWrite && (
        <div className="flex flex-wrap items-center gap-3 text-[13px]">
          <span className="text-fg-muted">The files you add next are labelled with</span>
          <label className="inline-flex items-center gap-2">
            <span className="font-mono text-xs text-fg-muted">User</span>
            <input
              type="text"
              value={user}
              onChange={(event) => setUser(event.target.value)}
              placeholder="j.alvarez"
              maxLength={255}
              className={FIELD}
            />
          </label>
          <label className="inline-flex items-center gap-2">
            <span className="font-mono text-xs text-fg-muted">Host</span>
            <input
              type="text"
              value={host}
              onChange={(event) => setHost(event.target.value)}
              placeholder="HL-FIN-WS014"
              maxLength={255}
              className={FIELD}
            />
          </label>
        </div>
      )}

      <SourceFiles
        incidentId={incident.id}
        kind="commands"
        filter={ofShell}
        uploadParams={params}
        expected={expected}
        match={match}
        title={`Sources — ${shell.label}`}
        help={<WhereToFind shell={shell} os={os} />}
        accept={shell.source.accept || undefined}
        showUser
        canWrite={canWrite}
        onChanged={changed}
        onView={setWholeFile}
      />

      {hasRecords && (
        <CommandsSection
          key={active}
          incident={incident}
          shell={shell}
          sources={readable}
          canWrite={canWrite}
          version={version}
        />
      )}

      {wholeFile && <SourceViewer incidentId={incident.id} source={wholeFile} onClose={() => setWholeFile(null)} />}
    </div>
  )
}
