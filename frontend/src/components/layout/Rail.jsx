import {
  Bell,
  Boxes,
  Fingerprint,
  FlaskConical,
  FolderClosed,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Search,
  Settings,
  UserCircle,
  UserCog,
  Workflow,
} from 'lucide-react'
import NikMark from '../ui/NikMark.jsx'
import { useAuth } from '../../context/AuthContext.jsx'
import { useContextMenu } from '../../context/ContextMenuContext.jsx'
import { describeRoles, rolesOf } from '../../domain/permissions.js'

/*
 * ============================================================================
 * RAIL — the narrow column of icons on the left edge
 * ============================================================================
 *
 * Always visible; an entry is shown to the accounts whose roles let them use
 * it. The entries are in the order of a working day: what there is to work on
 * (incidents, one's tasks, the dashboards), what the work is done with
 * (indicators, artifacts, the search, the playground for a command outside
 * any incident), then what is built (automations). An
 * entry that lists things opens the side panel; clicking it again closes the
 * panel, so the rail is also how the side panel collapses.
 *
 * At the foot: the notifications, Settings, and the account. Nothing here
 * opens a single section of Settings: those are reached from Settings.
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
 *   onSearch: () => void, onSettings: () => void, onAccount: () => void,
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
  onSettings,
  onAccount,
  settingsOpen = false,
  onAutomation,
  automationOpen = false,
  onTasks,
  tasksOpen = false,
  onDashboards,
  dashboardsOpen = false,
  onPlayground,
  playgroundOpen = false,
  onNotifications,
}) {
  const { currentUser, logout } = useAuth()
  const { openMenu } = useContextMenu()
  // With Settings or Automations open no panel is shown, and an entry leaves the page for its panel.
  const open = settingsOpen || automationOpen || tasksOpen || dashboardsOpen || playgroundOpen ? null : panel
  const toggle = (name) => onPanel(open === name ? null : name)
  const canRead = can('read')
  const roles = currentUser ? describeRoles(rolesOf(currentUser)) : ''
  const account = (event) =>
    openMenu(event, {
      title: `${currentUser.username} · ${roles}`,
      items: [
        { label: 'My account', icon: UserCog, onSelect: onAccount },
        'separator',
        { label: 'Sign out', icon: LogOut, onSelect: logout },
      ],
    })
  return (
    <nav
      aria-label="Sections"
      className="flex h-full w-14 shrink-0 flex-col items-stretch border-r border-line bg-sunken py-3"
    >
      <NikMark className="mx-auto mb-3 h-7 w-7 shrink-0" />
      {canRead && (
        <RailButton
          icon={FolderClosed}
          label={open === 'incidents' ? 'Hide the incidents' : 'Incidents'}
          active={open === 'incidents'}
          count={counts.incidents}
          onClick={() => toggle('incidents')}
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
      {canRead && (
        <RailButton
          icon={LayoutDashboard}
          label={dashboardsOpen ? 'Close dashboards' : 'Dashboards'}
          active={dashboardsOpen}
          onClick={onDashboards}
        />
      )}
      {canRead && (
        <>
          <RailButton
            icon={Fingerprint}
            label={
              open === 'iocs'
                ? 'Hide the Indicators page'
                : counts.alerts
                  ? `Indicators (${counts.alerts} new alerts)`
                  : 'Indicators'
            }
            active={open === 'iocs'}
            count={counts.iocs}
            alert={counts.alerts > 0}
            onClick={() => toggle('iocs')}
          />
          <RailButton
            icon={Boxes}
            label={open === 'artifacts' ? 'Hide the artifacts' : 'Artifacts'}
            active={open === 'artifacts'}
            count={counts.artifacts}
            onClick={() => toggle('artifacts')}
          />
          <RailButton icon={Search} label="Search (Ctrl+K)" onClick={onSearch} />
        </>
      )}
      {can('automation.run') && (
        <RailButton
          icon={FlaskConical}
          label={playgroundOpen ? 'Close the playground' : 'Playground'}
          active={playgroundOpen}
          onClick={onPlayground}
        />
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
      <RailButton
        icon={Settings}
        label={settingsOpen ? 'Close platform settings' : 'Open platform settings'}
        active={settingsOpen}
        onClick={onSettings}
      />
      {currentUser && (
        <RailButton icon={UserCircle} label={`Account: ${currentUser.username} (${roles})`} onClick={account} />
      )}
    </nav>
  )
}
