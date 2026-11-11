import { Boxes, DatabaseBackup, FolderClosed, ScrollText, Search, Settings, Users } from 'lucide-react'

/*
 * ============================================================================
 * RAIL — the narrow column of icons on the left edge
 * ============================================================================
 *
 * Always visible. The top icons choose what the side panel lists (incidents
 * or artifacts); clicking the active one closes the panel, so the rail is also
 * how the sidebar collapses. The bottom icons open the tools that used to sit
 * at the foot of the sidebar.
 */

function RailButton({ icon: Icon, label, active = false, onClick, count = null }) {
  return (
    <button
      type="button"
      title={label}
      aria-label={label}
      aria-pressed={active || undefined}
      onClick={onClick}
      className={[
        'relative flex h-11 w-full items-center justify-center border-l-2 transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent',
        active ? 'border-accent bg-panel text-fg' : 'border-transparent text-fg-muted hover:bg-panel/60 hover:text-fg',
      ].join(' ')}
    >
      <Icon className="h-5 w-5" aria-hidden="true" />
      {count != null && count > 0 && (
        <span aria-hidden="true" className="absolute right-1 top-1 font-mono text-[9px] leading-none text-fg-muted">
          {count > 99 ? '99+' : count}
        </span>
      )}
    </button>
  )
}

/**
 * @param {{
 *   panel: 'incidents' | 'artifacts' | null,   // the open side panel
 *   onPanel: (panel: string | null) => void,
 *   counts: { incidents: number, artifacts: number },
 *   isAdmin: boolean,
 *   onSearch: () => void, onAudit: () => void, onUsers: () => void,
 *   onBackup: () => void, onSettings: () => void,
 * }} props
 */
export default function Rail({ panel, onPanel, counts, isAdmin, onSearch, onAudit, onUsers, onBackup, onSettings }) {
  const toggle = (name) => onPanel(panel === name ? null : name)
  return (
    <nav
      aria-label="Sections"
      className="flex h-full w-14 shrink-0 flex-col items-stretch border-r border-line bg-sunken py-3"
    >
      <span
        aria-hidden="true"
        className="mx-auto mb-3 bg-accent px-2 py-1 font-mono text-sm font-extrabold leading-tight text-canvas"
      >
        &gt;_
      </span>
      <RailButton
        icon={FolderClosed}
        label={panel === 'incidents' ? 'Hide the incidents' : 'Incidents'}
        active={panel === 'incidents'}
        count={counts.incidents}
        onClick={() => toggle('incidents')}
      />
      <RailButton
        icon={Boxes}
        label={panel === 'artifacts' ? 'Hide the artifacts' : 'Artifacts'}
        active={panel === 'artifacts'}
        count={counts.artifacts}
        onClick={() => toggle('artifacts')}
      />
      <RailButton icon={Search} label="Search (Ctrl+K)" onClick={onSearch} />
      <span className="flex-1" />
      <RailButton icon={ScrollText} label="Audit log" onClick={onAudit} />
      <RailButton icon={Users} label="Users" onClick={onUsers} />
      {isAdmin && <RailButton icon={DatabaseBackup} label="Full backup" onClick={onBackup} />}
      <RailButton icon={Settings} label="Open platform settings" onClick={onSettings} />
    </nav>
  )
}
