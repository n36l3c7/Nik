import {
  Bell,
  Boxes,
  Fingerprint,
  FlaskConical,
  FolderClosed,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Settings,
  UserCircle,
  UserCog,
  Workflow,
} from 'lucide-react'
import NikMark from '../ui/NikMark.jsx'
import { useAuth } from '../../context/AuthContext.jsx'
import { useContextMenu } from '../../context/ContextMenuContext.jsx'
import { describeRoles, rolesOf } from '../../domain/permissions.js'
import { RAIL_SECTIONS } from '../../domain/sections.js'

/*
 * ============================================================================
 * RAIL — the narrow column of icons on the left edge
 * ============================================================================
 *
 * Always visible; an entry is shown to the accounts whose roles let them use
 * it. From the top: the dashboards (how things stand), the incidents, one's
 * tasks, then what the work is done with (the artifacts, the indicators), the
 * automations and, last, the playground for a command outside any incident
 * (domain/sections.js holds the order). The search is not here: it is the bar
 * in the middle of every page's header (SearchBar.jsx).
 *
 * An entry always shows the first screen of its section, from wherever it is
 * pressed; pressed there, it does nothing. It is not a switch: the side panel
 * of the artifacts and of the indicators is hidden with the button in its own
 * header, a page with its own close button.
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

const ICONS = {
  dashboards: LayoutDashboard,
  incidents: FolderClosed,
  tasks: ListChecks,
  artifacts: Boxes,
  iocs: Fingerprint,
  automation: Workflow,
  playground: FlaskConical,
}

/** What an entry says of what waits in its section, after its name. */
function labelOf(section, counts) {
  if (section.id === 'tasks' && counts.tasks) {
    const overdue = counts.tasksOverdue ? `, ${counts.tasksOverdue} overdue` : ''
    return `My tasks (${counts.tasks} ${counts.tasks === 1 ? 'waits' : 'wait'}${overdue})`
  }
  if (section.id === 'iocs' && counts.alerts) return `Indicators (${counts.alerts} new alerts)`
  if (section.id === 'automation' && counts.approvals) {
    return `Automations (${counts.approvals} ${counts.approvals === 1 ? 'approval waits' : 'approvals wait'})`
  }
  return section.label
}

const countOf = (id, counts) =>
  ({
    incidents: counts.incidents,
    tasks: counts.tasks,
    artifacts: counts.artifacts,
    iocs: counts.iocs,
    automation: counts.approvals,
  })[id] ?? null

const alertOf = (id, counts) =>
  (id === 'tasks' && counts.tasksOverdue > 0) ||
  (id === 'iocs' && counts.alerts > 0) ||
  (id === 'automation' && counts.approvals > 0)

/**
 * @param {{
 *   active: string | null,                        // the section shown: an id of domain/sections.js, or 'settings'
 *   onSection: (id: string) => void,              // go to the first screen of a section
 *   counts: { incidents: number, artifacts: number, iocs: number, alerts: number, approvals: number,
 *             tasks: number, tasksOverdue: number, unread: number },
 *   can: (...permissions: string[]) => boolean,   // what the signed-in account may do
 *   onAccount: () => void,
 *   onNotifications: () => void,
 *   onSignOut: () => void,
 * }} props
 */
export default function Rail({ active, onSection, counts, can, onAccount, onNotifications, onSignOut }) {
  const { currentUser } = useAuth()
  const { openMenu } = useContextMenu()
  const canRead = can('read')
  const roles = currentUser ? describeRoles(rolesOf(currentUser)) : ''
  const account = (event) =>
    openMenu(event, {
      title: `${currentUser.username} · ${roles}`,
      items: [
        { label: 'My account', icon: UserCog, onSelect: onAccount },
        'separator',
        { label: 'Sign out', icon: LogOut, onSelect: onSignOut },
      ],
    })
  return (
    <nav
      aria-label="Sections"
      className="flex h-full w-14 shrink-0 flex-col items-stretch border-r border-line bg-sunken py-3"
    >
      <NikMark className="mx-auto mb-3 h-7 w-7 shrink-0" />
      {RAIL_SECTIONS.filter((section) => can(section.permission)).map((section) => (
        <RailButton
          key={section.id}
          icon={ICONS[section.id]}
          label={labelOf(section, counts)}
          active={active === section.id}
          count={countOf(section.id, counts)}
          alert={alertOf(section.id, counts)}
          onClick={() => onSection(section.id)}
        />
      ))}
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
        label="Platform settings"
        active={active === 'settings'}
        onClick={() => onSection('settings')}
      />
      {currentUser && (
        <RailButton icon={UserCircle} label={`Account: ${currentUser.username} (${roles})`} onClick={account} />
      )}
    </nav>
  )
}
