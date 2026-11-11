import { Flag, MessageSquarePlus } from 'lucide-react'

/**
 * The flag and comment items of a flaggable thing in an incident.
 * @param {{ incident: object, flaggable: object, toggleFlag: Function, addFlagComment: Function,
 *           askText: Function, what?: string }} options `what` names it in the labels ("indicator").
 */
export function flagItems({ incident, flaggable, toggleFlag, addFlagComment, askText, what = '' }) {
  const flagged = Boolean(incident.flags?.[flaggable.key])
  const noun = what ? ` ${what}` : ''
  return [
    {
      label: flagged ? 'Remove the flag' : what ? `Flag the${noun}` : 'Flag as malicious',
      icon: Flag,
      onSelect: () => toggleFlag(incident.id, flaggable),
    },
    {
      label: 'Add a comment…',
      icon: MessageSquarePlus,
      onSelect: async () => {
        const comment = await askText({
          title: `Comment on the${noun || ' event'}`,
          label: flagged ? 'Comment' : `Comment (the${noun || ' event'} is flagged too)`,
          placeholder: 'What it shows',
          confirm: 'Add comment',
        })
        if (!comment) return
        if (!flagged) toggleFlag(incident.id, flaggable)
        addFlagComment(incident.id, flaggable.key, comment)
      },
    },
  ]
}
