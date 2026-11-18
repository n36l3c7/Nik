import { useTasks } from '../../context/TasksContext.jsx'
import { setPath } from '../../lib/location.js'
import { formatDateTime } from '../../lib/time.js'
import { notificationKind, safeLink } from '../../domain/timers.js'
import { Badge, Button, Modal } from '../ui/index.js'

/*
 * What the account was told: a task given, a reminder, an approval that
 * waits, a mention in a War Room, an SLA past its time. The newest first;
 * opening one goes where it points and marks it read.
 */

const COLORS = { overdue: 'red', SLA: 'red', approval: 'amber', task: 'cyan', reminder: 'amber', mention: 'violet' }

/** @param {{ onClose: () => void }} props */
export default function NotificationsDialog({ onClose }) {
  const { notifications, unread, readNotifications } = useTasks()

  const open = (item) => {
    readNotifications([item.id])
    const link = safeLink(item.link)
    if (link) setPath(link)
    onClose()
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="Notifications"
      maxWidth="max-w-xl"
      footer={
        <Button variant="secondary" size="sm" disabled={unread === 0} onClick={() => readNotifications([])}>
          Mark all as read
        </Button>
      }
    >
      {notifications.length === 0 ? (
        <p className="text-sm text-fg-muted">
          Nothing yet. You are told here when a task is given to you, an approval waits, someone mentions you in a War
          Room, or a timer of an incident you own passes its time.
        </p>
      ) : (
        <ul aria-label="Notifications" className="flex flex-col divide-y divide-line-soft border border-line">
          {notifications.map((item) => {
            const kind = notificationKind(item.kind)
            return (
              <li key={item.id}>
                <button
                  type="button"
                  onClick={() => open(item)}
                  className={[
                    'flex w-full items-start gap-3 px-3 py-2 text-left hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent',
                    item.read ? 'opacity-60' : '',
                  ].join(' ')}
                >
                  <span className="w-20 shrink-0">
                    <Badge color={COLORS[kind] ?? 'slate'}>{kind}</Badge>
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className={`block text-sm ${item.read ? 'text-fg-muted' : 'font-medium text-fg'}`}>
                      {item.text}
                    </span>
                    <span className="block font-mono text-[11px] text-fg-subtle">
                      {formatDateTime(Date.parse(item.at))}
                      {item.read ? '' : ' · new'}
                    </span>
                  </span>
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </Modal>
  )
}
