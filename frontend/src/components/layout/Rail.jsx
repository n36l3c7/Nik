import {
  Bell,
  Boxes,
  DatabaseBackup,
  Fingerprint,
  FolderClosed,
  ListChecks,
  ScrollText,
  Search,
  Settings,
  Users,
  Workflow,
} from 'lucide-react'

/*
 * ============================================================================
 * RAIL — the narrow column of icons on the left edge
 * ============================================================================
 *
 * Always visible; an entry is shown to the accounts whose roles let them use
 * it. The top icons choose what the side panel lists (incidents
 * or artifacts); clicking the active one closes the panel, so the rail is also
 * how the sidebar collapses. The bottom icons open the tools that used to sit
 * at the foot of the sidebar.
 */

function RailButton({ icon: Icon, label, active = false, onClick, count = null, alert = false }) {
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
      {alert && (
        <span aria-hidden="true" className="absolute bottom-1.5 right-1.5 h-1.5 w-1.5 rounded-full bg-high-line" />
      )}
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
 *   panel: 'incidents' | 'artifacts' | 'iocs' | null,   // the open side panel
 *   onPanel: (panel: string | null) => void,
 *   counts: { incidents: number, artifacts: number, iocs: number, alerts: number, approvals: number,
 *             tasks: number, tasksOverdue: number, unread: number },
 *   can: (...permissions: string[]) => boolean,   // what the signed-in account may do
 *   onSearch: () => void, onAudit: () => void, onUsers: () => void,
 *   onBackup: () => void, onSettings: () => void,
 *   settingsOpen?: boolean,                        // the Settings page is shown
 *   onAutomation: () => void,
 *   automationOpen?: boolean,                      // the Automations area is shown
 * }} props
 */
export default function Rail({
  panel,
  onPanel,
  counts,
  can,
  onSearch,
  onAudit,
  onUsers,
  onBackup,
  onSettings,
  settingsOpen = false,
  onAutomation,
  automationOpen = false,
  onTasks,
  tasksOpen = false,
  onNotifications,
}) {
  // With Settings or Automations open no panel is shown, and an entry leaves the page for its panel.
  const open = settingsOpen || automationOpen || tasksOpen ? null : panel
  const toggle = (name) => onPanel(open === name ? null : name)
  const canRead = can('read')
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
      {canRead && (
        <>
          <RailButton
            icon={FolderClosed}
            label={open === 'incidents' ? 'Hide the incidents' : 'Incidents'}
            active={open === 'incidents'}
            count={counts.incidents}
            onClick={() => toggle('incidents')}
          />
          <RailButton
            icon={Boxes}
            label={open === 'artifacts' ? 'Hide the artifacts' : 'Artifacts'}
            active={open === 'artifacts'}
            count={counts.artifacts}
            onClick={() => toggle('artifacts')}
          />
          <RailButton
            icon={Fingerprint}
            label={
              open === 'iocs'
                ? 'Hide the IoC library'
                : counts.alerts
                  ? `IoC library (${counts.alerts} new alerts)`
                  : 'IoC library'
            }
            active={open === 'iocs'}
            count={counts.iocs}
            alert={counts.alerts > 0}
            onClick={() => toggle('iocs')}
          />
          <RailButton icon={Search} label="Search (Ctrl+K)" onClick={onSearch} />
        </>
      )}
      {can('automation.run') && (
        <RailButton
          icon={Workflow}
          label={
            automationOpen
              ? 'Close automations'
              : counts.approvals
                ? `Automations (${counts.approvals} ${counts.approvals === 1 ? 'approval waits' : 'approvals wait'})`
                : 'Automations'
          }
          active={automationOpen}
          count={counts.approvals}
          alert={counts.approvals > 0}
          onClick={onAutomation}
        />
      )}
      {canRead && (
        <RailButton
          icon={ListChecks}
          label={
            tasksOpen
              ? 'Close my tasks'
              : counts.tasks
                ? `My tasks (${counts.tasks} ${counts.tasks === 1 ? 'waits' : 'wait'}${counts.tasksOverdue ? `, ${counts.tasksOverdue} overdue` : ''})`
                : 'My tasks'
          }
          active={tasksOpen}
          count={counts.tasks}
          alert={counts.tasksOverdue > 0}
          onClick={onTasks}
        />
      )}
      <span className="flex-1" />
      {canRead && (
        <RailButton
          icon={Bell}
          label={counts.unread ? `Notifications (${counts.unread} new)` : 'Notifications'}
          count={counts.unread}
          alert={counts.unread > 0}
          onClick={onNotifications}
        />
      )}
      {can('audit.read') && <RailButton icon={ScrollText} label="Audit log" onClick={onAudit} />}
      {can('admin') && <RailButton icon={Users} label="Users" onClick={onUsers} />}
      {can('admin') && <RailButton icon={DatabaseBackup} label="Full backup" onClick={onBackup} />}
      <RailButton
        icon={Settings}
        label={settingsOpen ? 'Close platform settings' : 'Open platform settings'}
        active={settingsOpen}
        onClick={onSettings}
      />
    </nav>
  )
}
