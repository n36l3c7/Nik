import { useState } from 'react'
import { Pencil, Plus, Trash2, UserRound } from 'lucide-react'
import { Button, Modal } from '../../ui/index.js'
import { profileNameError, profileRowCount, sortedProfiles } from '../../../utils/browserProfiles.js'

/*
 * ============================================================================
 * PROFILE BAR — the profiles of the active browser (Default, Profile 1, …)
 * ============================================================================
 * Chips to switch profile (with their row count), plus add / rename / delete.
 * Each profile owns its files and data; a browser always keeps one profile,
 * so the last one cannot be deleted. Deleting keeps the flags placed on its
 * rows (they are investigative decisions): the timeline marks them.
 *
 * @param {{
 *   browser: object,                 // registry entry (config/browsers.js)
 *   slot: object,                    // { activeProfile, profiles }
 *   activeProfileId: string,
 *   onSelect: (profileId: string) => void,
 *   onAdd: (name: string) => void,
 *   onRename: (profileId: string, name: string) => void,
 *   onDelete: (profileId: string) => void,
 * }} props
 */
export default function ProfileBar({ browser, slot, activeProfileId, onSelect, onAdd, onRename, onDelete }) {
  // { mode: 'add' | 'rename', name } while the name dialog is open.
  const [dialog, setDialog] = useState(null)
  const [confirmDelete, setConfirmDelete] = useState(false)

  const profiles = sortedProfiles(slot)
  const active = slot.profiles[activeProfileId] ?? profiles[0]
  const nameError = dialog
    ? profileNameError(slot, dialog.name, dialog.mode === 'rename' ? active.id : null)
    : null
  const canDelete = profiles.length > 1

  const submitName = (event) => {
    event.preventDefault()
    if (nameError) return
    if (dialog.mode === 'add') onAdd(dialog.name.trim())
    else onRename(active.id, dialog.name.trim())
    setDialog(null)
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="mr-1 inline-flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
        <UserRound className="h-3.5 w-3.5" />
        Profiles
      </span>
      <div role="tablist" aria-label={`${browser.label} profiles`} className="flex flex-wrap gap-1.5">
        {profiles.map((profile) => {
          const isActive = profile.id === active.id
          const rows = profileRowCount(profile)
          return (
            <button
              key={profile.id}
              type="button"
              role="tab"
              aria-selected={isActive}
              onClick={() => onSelect(profile.id)}
              className={[
                'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500',
                isActive
                  ? 'border-cyan-500/60 bg-cyan-50 text-cyan-700 dark:border-cyan-500/50 dark:bg-cyan-500/10 dark:text-cyan-300'
                  : 'border-slate-200 text-slate-600 hover:bg-slate-50 dark:border-slate-800 dark:text-slate-400 dark:hover:bg-slate-800/60',
              ].join(' ')}
            >
              {profile.name}
              {rows > 0 && <span className="tabular-nums opacity-70">{rows.toLocaleString('en-US')}</span>}
            </button>
          )
        })}
      </div>
      <div className="ml-auto flex items-center gap-1.5">
        <Button variant="secondary" size="sm" icon={Plus} onClick={() => setDialog({ mode: 'add', name: '' })}>
          Add profile
        </Button>
        <Button
          variant="ghost"
          size="sm"
          icon={Pencil}
          aria-label={`Rename profile "${active.name}"`}
          title="Rename profile"
          onClick={() => setDialog({ mode: 'rename', name: active.name })}
        />
        <Button
          variant="ghost"
          size="sm"
          icon={Trash2}
          aria-label={`Delete profile "${active.name}"`}
          title={canDelete ? 'Delete profile' : 'A browser keeps at least one profile'}
          disabled={!canDelete}
          onClick={() => setConfirmDelete(true)}
        />
      </div>

      {/* Add / rename dialog */}
      <Modal
        open={dialog !== null}
        onClose={() => setDialog(null)}
        title={dialog?.mode === 'rename' ? `Rename profile "${active.name}"` : `New ${browser.label} profile`}
        footer={
          <>
            <Button variant="secondary" onClick={() => setDialog(null)}>
              Cancel
            </Button>
            <Button type="submit" form="form-browser-profile" disabled={Boolean(nameError)}>
              {dialog?.mode === 'rename' ? 'Rename' : 'Add profile'}
            </Button>
          </>
        }
      >
        <form id="form-browser-profile" onSubmit={submitName} className="space-y-2">
          <label htmlFor="browser-profile-name" className="block text-sm font-medium text-slate-700 dark:text-slate-300">
            Profile name
          </label>
          <input
            id="browser-profile-name"
            type="text"
            value={dialog?.name ?? ''}
            onChange={(e) => setDialog((d) => ({ ...d, name: e.target.value }))}
            placeholder={browser.profileHint ? 'e.g. Profile 1' : 'e.g. Work'}
            maxLength={60}
            autoFocus
            aria-invalid={Boolean(nameError) && Boolean(dialog?.name)}
            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 dark:border-slate-800 dark:bg-slate-950 dark:text-white dark:placeholder:text-slate-500"
          />
          {nameError && dialog?.name && <p className="text-xs text-red-600 dark:text-red-400">{nameError}</p>}
          {browser.profileHint && (
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Tip: use the name of the profile folder ({browser.profileHint}).
            </p>
          )}
        </form>
      </Modal>

      {/* Delete confirmation */}
      <Modal
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        title={`Delete profile "${active.name}"`}
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirmDelete(false)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              icon={Trash2}
              onClick={() => {
                onDelete(active.id)
                setConfirmDelete(false)
              }}
            >
              Delete profile
            </Button>
          </>
        }
      >
        <p className="text-sm text-slate-600 dark:text-slate-300">
          The <strong>{browser.label}</strong> profile <strong>{active.name}</strong> and all its
          imported data ({profileRowCount(active).toLocaleString('en-US')} rows) will be deleted.
          Flags placed on its entries are kept and marked as coming from a deleted profile.
          This action is irreversible.
        </p>
      </Modal>
    </div>
  )
}
