/*
 * Archiving an incident (7.0): the words and the rules the screens share. The server decides
 * (routers/archive.py); this is what is shown before it is asked.
 */

/** What archiving does, said before it is done. */
export const ARCHIVE_EFFECT =
  'Archiving drops its host records from the database. The original files, the reports, the flags and the notes are kept, and the incident becomes read-only.'

/** What taking it out does. */
export const UNARCHIVE_EFFECT =
  'Taking it out of the archive makes it writable again and reads its files again: the records come back when the reading is done.'

/** The sentence a page of host evidence and the timeline show for an archived incident. */
export const ARCHIVED_RECORDS_NOTE =
  'Archived: the records are not loaded. Take the incident out of the archive to read them again.'

/** Whether the incident is archived. */
export const isArchived = (incident) => Boolean(incident?.archivedAt)

/** Whether the "Archive" action is offered for it: only a closed incident that is not archived yet. */
export const canArchive = (incident) => incident?.status === 'closed' && !isArchived(incident)

/** The choices of the list's filter, by the value `GET /incidents?archived=` takes. */
export const ARCHIVED_FILTER_OPTIONS = [
  { value: 'exclude', label: 'Archived: no' },
  { value: 'only', label: 'Archived: only' },
  { value: 'include', label: 'Archived: include' },
]

/** The value of that filter that is sent: `exclude` is what the server does without it. */
export const archivedParam = (value) => (value === 'only' || value === 'include' ? value : '')

export const DAYS_RANGE = { min: 1, max: 3650 }

/** The sentence for a number of days the rule cannot take, or '' when it is fine. */
export function daysProblem(value) {
  const days = Number(value)
  if (!Number.isInteger(days) || days < DAYS_RANGE.min || days > DAYS_RANGE.max) {
    return `Days: a whole number from ${DAYS_RANGE.min} to ${DAYS_RANGE.max}.`
  }
  return ''
}
