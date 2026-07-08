import { useEffect, useMemo, useState } from 'react'
import { FolderInput, Info, Sparkles, Trash2, Upload } from 'lucide-react'
import { Button, Card, Modal } from '../../ui/index.js'
import FileUploadZone from '../browser/FileUploadZone.jsx'
import CommandsSection from './CommandsSection.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { parseShellHistory } from '../../../services/shellParsers.js'
import { getDemoShellData } from '../../../services/demoData.js'
import { SHELLS, getShellById, buildDefaultShellData, shellsForOs } from '../../../config/shells.js'
import { getOsById, DEFAULT_OS } from '../../../config/os.js'

/*
 * "Command History" tab: one SUB-TAB per shell (Bash, Zsh, Fish, PowerShell),
 * mirroring the Browser Forensics tab. Each shell exposes a single history
 * file source, its command list, SOC detection, per-row flagging and the
 * ability to clear its data.
 *
 * Which shells are offered is driven by the incident's host OS (a Windows host
 * shows PowerShell first; a Linux/macOS host shows the POSIX shells) — but any
 * shell that already has imported data is always shown, so nothing is hidden
 * after an OS change or a JSON import.
 */

export default function CommandHistoryTab({ incident }) {
  const { updateShellData, setActiveShell, clearShellData } = useIncidents()

  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [confirmClear, setConfirmClear] = useState(false)

  const commandsData = incident.data.commands
  const os = getOsById(incident.os) ? incident.os : DEFAULT_OS

  // Shells relevant to this host: those shipping on the OS, plus any that
  // already hold imported data.
  const visibleShells = useMemo(() => {
    const onOs = new Set(shellsForOs(os).map((s) => s.id))
    return SHELLS.filter(
      (s) => onOs.has(s.id) || (commandsData.shells[s.id]?.commands?.length ?? 0) > 0,
    )
  }, [os, commandsData.shells])

  // Active shell: keep the stored one if still visible, else the first visible.
  const activeShellId =
    visibleShells.some((s) => s.id === commandsData.activeShell) && getShellById(commandsData.activeShell)
      ? commandsData.activeShell
      : (visibleShells[0]?.id ?? SHELLS[0].id)
  const shell = getShellById(activeShellId) ?? SHELLS[0]

  const current = commandsData.shells[activeShellId] ?? buildDefaultShellData()
  const source = shell.source
  const sourceMeta = current.meta?.[source.key] ?? null
  const hasData = (current.commands?.length ?? 0) > 0

  // If the active shell drifts out of the visible set (e.g. OS change), snap it.
  useEffect(() => {
    setError(null)
    setLoading(false)
    if (!visibleShells.some((s) => s.id === activeShellId)) {
      setActiveShell(incident.id, visibleShells[0]?.id ?? SHELLS[0].id)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeShellId, incident.id])

  /* ---- Import the history file ---- */
  const handleFile = async (file) => {
    setError(null)
    setLoading(true)
    try {
      const { commands, format } = await parseShellHistory(file, shell)
      updateShellData(
        incident.id,
        activeShellId,
        {
          commands,
          meta: {
            [source.key]: {
              fileName: file.name,
              format,
              rows: commands.length,
              importedAt: new Date().toISOString(),
            },
          },
        },
        {
          action: 'command.upload',
          details: `Imported ${shell.label} history (${commands.length} commands)`,
        },
      )
    } catch (err) {
      setError(err?.message ?? 'Unexpected error while parsing the file.')
    } finally {
      setLoading(false)
    }
  }

  const handleRemoveSource = () => {
    setError(null)
    clearShellData(incident.id, activeShellId)
  }

  /* ---- Load demo data into the active shell ---- */
  const handleLoadDemo = () => {
    const demo = getDemoShellData(shell)
    setError(null)
    updateShellData(
      incident.id,
      activeShellId,
      {
        commands: demo.commands,
        meta: {
          [source.key]: {
            fileName: 'Demo data',
            format: 'demo',
            rows: demo.commands.length,
            importedAt: new Date().toISOString(),
          },
        },
      },
      { action: 'command.demo', details: `Loaded demo commands into ${activeShellId}` },
    )
  }

  const handleConfirmClear = () => {
    clearShellData(incident.id, activeShellId)
    setError(null)
    setConfirmClear(false)
  }

  const sourcePath = source.paths?.[os] ?? source.paths?.windows ?? source.paths?.linux ?? ''

  return (
    <div className="space-y-6">
      {/* -------- Shell sub-tabs -------- */}
      <div
        role="tablist"
        aria-label="Shell"
        className="flex flex-wrap gap-2 rounded-xl border border-slate-200 bg-white p-2 dark:border-slate-800 dark:bg-slate-900"
      >
        {visibleShells.map((s) => {
          const isActive = s.id === activeShellId
          const ShellIcon = s.icon
          const count = commandsData.shells[s.id]?.commands?.length ?? 0
          return (
            <button
              key={s.id}
              type="button"
              role="tab"
              aria-selected={isActive}
              onClick={() => setActiveShell(incident.id, s.id)}
              className={[
                'inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500',
                isActive
                  ? 'border-cyan-500/60 bg-cyan-50 text-cyan-700 dark:border-cyan-500/50 dark:bg-cyan-500/10 dark:text-cyan-300'
                  : 'border-transparent text-slate-600 hover:bg-slate-50 dark:text-slate-400 dark:hover:bg-slate-800/60',
              ].join(' ')}
            >
              <ShellIcon className={`h-4 w-4 ${isActive ? '' : s.accent}`} />
              {s.label}
              {count > 0 && (
                <span
                  className={[
                    'rounded-full px-1.5 text-xs tabular-nums',
                    isActive
                      ? 'bg-cyan-600/20 text-cyan-700 dark:text-cyan-300'
                      : 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400',
                  ].join(' ')}
                >
                  {count.toLocaleString('en-US')}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {/* -------- "Where to find the file" note (disappears once loaded) -------- */}
      {!sourceMeta && (
        <div className="flex gap-3 rounded-xl border border-cyan-200 bg-cyan-50/60 p-4 text-sm dark:border-cyan-500/30 dark:bg-cyan-500/5">
          <FolderInput className="mt-0.5 h-5 w-5 shrink-0 text-cyan-600 dark:text-cyan-400" />
          <div className="min-w-0 space-y-1.5">
            <p className="font-medium text-slate-700 dark:text-slate-200">
              Where to find the {shell.label} history ({getOsById(os)?.label ?? os})
            </p>
            <p className="text-xs text-slate-600 dark:text-slate-400">
              <span className="font-medium">{source.label}:</span>{' '}
              <span className="break-all font-mono text-[11px] text-slate-500 dark:text-slate-400">
                {sourcePath}
              </span>
            </p>
            <p className="text-[11px] text-slate-400 dark:text-slate-500">{shell.timestamps}</p>
          </div>
        </div>
      )}

      {/* -------- Data source card -------- */}
      <Card
        title={`Data source — ${shell.label}`}
        icon={Upload}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" icon={Sparkles} onClick={handleLoadDemo}>
              Load demo data
            </Button>
            {hasData && (
              <Button variant="danger" size="sm" icon={Trash2} onClick={() => setConfirmClear(true)}>
                Clear {shell.label}
              </Button>
            )}
          </div>
        }
      >
        <div className="grid gap-4 md:grid-cols-1">
          <FileUploadZone
            label={source.label}
            description={source.hint}
            icon={source.icon}
            accept={source.accept}
            pathHint={sourcePath}
            meta={sourceMeta}
            loading={loading}
            error={error}
            onFile={handleFile}
            onClear={handleRemoveSource}
          />
        </div>
      </Card>

      {/* -------- Commands section -------- */}
      <CommandsSection incident={incident} shellId={activeShellId} commands={current.commands} />

      {/* Informational note about timestamps */}
      <p className="flex items-center justify-center gap-1.5 text-center text-xs text-slate-500 dark:text-slate-400">
        <Info className="h-3.5 w-3.5 shrink-0" />
        {shell.timestamps}
      </p>

      {/* -------- Confirm "clear shell" modal -------- */}
      <Modal
        open={confirmClear}
        onClose={() => setConfirmClear(false)}
        title={`Clear ${shell.label} history`}
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirmClear(false)}>
              Cancel
            </Button>
            <Button variant="danger" icon={Trash2} onClick={handleConfirmClear}>
              Clear {shell.label}
            </Button>
          </>
        }
      >
        <p className="text-sm text-slate-600 dark:text-slate-300">
          You are about to delete all imported <strong>{shell.label}</strong> commands in the
          incident <strong>{incident.name}</strong>. Other shells are left untouched. This action is
          irreversible.
        </p>
      </Modal>
    </div>
  )
}
