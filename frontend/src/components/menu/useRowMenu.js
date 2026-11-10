import { useCallback } from 'react'
import { Braces, Copy, Flag, ListTree, MessageSquarePlus } from 'lucide-react'
import { useContextMenu } from '../../context/ContextMenuContext.jsx'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useNavigation } from '../../context/NavigationContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { formatDateTime } from '../../lib/time.js'

/*
 * The right-click menu of an event row, the same in every table: flag or
 * unflag it, add a comment (flagging it first), copy it as text or JSON, and
 * show it in the Timeline. Use:
 *   const rowMenu = useRowMenu(incident)
 *   <DataTable onRowContextMenu={(event, row) => rowMenu(event, { flaggable, record: row })} />
 * `flaggable` is the payload the table's flag button passes to toggleFlag().
 */

const INTERNAL = /^(_|soc$|kind$)/

/** The row's own fields, without the UI's derived ones, for "Copy as JSON". */
function plain(record) {
  return Object.fromEntries(Object.entries(record ?? {}).filter(([key]) => !INTERNAL.test(key)))
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

export function useRowMenu(incident, { timeline = true } = {}) {
  const { openMenu, askText } = useContextMenu()
  const { toggleFlag, addFlagComment } = useIncidents()
  const { goTo } = useNavigation()
  const { showToast } = useToast()

  return useCallback(
    (event, { flaggable, record }) => {
      if (!incident || !flaggable) return false
      const flagged = Boolean(incident.flags?.[flaggable.key])
      const time = Number.isFinite(flaggable.time) ? formatDateTime(flaggable.time) : ''
      const text = [time, flaggable.title, flaggable.url].filter(Boolean).join('  ')
      const notify = async (content, what) =>
        showToast({ message: (await copy(content)) ? `${what} copied.` : 'The browser refused to copy.' })
      return openMenu(event, {
        title: flaggable.title || flaggable.url || 'Event',
        items: [
          {
            label: flagged ? 'Remove the flag' : 'Flag as malicious',
            icon: Flag,
            onSelect: () => toggleFlag(incident.id, flaggable),
          },
          {
            label: 'Add a comment…',
            icon: MessageSquarePlus,
            onSelect: async () => {
              const comment = await askText({
                title: 'Comment on the event',
                label: flagged ? 'Comment' : 'Comment (the event is flagged too)',
                placeholder: 'What this event shows',
                confirm: 'Add comment',
              })
              if (!comment) return
              if (!flagged) toggleFlag(incident.id, flaggable)
              addFlagComment(incident.id, flaggable.key, comment)
            },
          },
          'separator',
          { label: 'Copy as text', icon: Copy, onSelect: () => notify(text, 'Row') },
          {
            label: 'Copy as JSON',
            icon: Braces,
            onSelect: () => notify(JSON.stringify(plain(record), null, 2), 'Row JSON'),
          },
          timeline && 'separator',
          timeline && {
            label: 'Show in the Timeline',
            icon: ListTree,
            onSelect: () => goTo('timeline', { search: flaggable.title || flaggable.url || '' }),
          },
        ],
      })
    },
    [incident, openMenu, askText, toggleFlag, addFlagComment, goTo, showToast, timeline],
  )
}
