/*
 * What the screens say about a collection (a triage zip of host evidence listed, then imported on request):
 * the shape of its row in `GET …/evidence/sources` (`state`, `members` counts, `members.importing`) and of the
 * list of members of `GET …/evidence/collections/{id}` (backend/app/evidence/collections.py).
 */

export const COLLECTION_KIND = 'collection'
export const COLLECTION_SOURCE = 'collection.zip'

/** Whether a source is a collection (a zip), as opposed to the source a psort export becomes. */
export const isCollection = (source) => source?.kind === COLLECTION_KIND && source?.source === COLLECTION_SOURCE

/** The filter tabs of the list of members: `status` is the API's, `count` the key of `counts`. */
export const MEMBER_TABS = [
  { id: 'all', label: 'All', count: 'all' },
  { id: 'importable', label: 'Importable', count: 'importable' },
  { id: 'imported', label: 'Already imported', count: 'imported' },
  { id: 'skipped', label: 'Skipped', count: 'skipped' },
  { id: 'executables', label: 'Programs', count: 'executables' },
  { id: 'unrecognised', label: 'Not recognised', count: 'unrecognised' },
]

/** The tabs with their counts (zero while the list is not read). */
export const memberTabs = (counts = {}) =>
  MEMBER_TABS.map((tab) => ({ id: tab.id, label: tab.label, count: counts[tab.count] ?? 0 }))

/** The sections a member can go to, as the page that shows them says. */
export const SECTION_LABELS = {
  eventlog: 'Event Logs',
  syslog: 'Event Logs (Linux, macOS)',
  endpoint: 'Endpoint Artifacts',
  browser: 'Browser Forensics',
  commands: 'Command History',
  disk: 'Disk (NTFS)',
}

export const sectionLabel = (kind) => SECTION_LABELS[kind] ?? kind ?? ''

/** The kinds the "kinds" checkboxes offer, from `counts.byKind`: `{ kind, label, count }`, by name. */
export function kindOptions(byKind = {}) {
  return Object.entries(byKind)
    .map(([kind, count]) => ({ kind, label: sectionLabel(kind), count }))
    .sort((a, b) => a.label.localeCompare(b.label))
}

/** `kind` with `value` switched: the checkboxes' selection. */
export const toggleKind = (kinds, value) =>
  kinds.includes(value) ? kinds.filter((kind) => kind !== value) : [...kinds, value]

/** What a member is to the import: a word for its State column and the colour of its pill. */
export function memberState(member) {
  if (member.executable)
    return {
      id: 'program',
      label: 'program',
      color: 'amber',
      title: 'Listed, never imported as evidence: send it to Malware Analysis',
    }
  if (member.skip) return { id: 'skipped', label: 'skipped', color: 'slate', title: member.skip }
  if (member.imported) {
    return member.alreadyImported
      ? { id: 'already', label: 'already imported', color: 'slate', title: 'The incident holds this file already' }
      : { id: 'imported', label: 'imported', color: 'emerald', title: 'Imported from this collection' }
  }
  if (member.importable) return { id: 'importable', label: 'importable', color: 'cyan', title: 'Nik reads this file' }
  return { id: 'unrecognised', label: 'not recognised', color: 'slate', title: 'No reader of Nik takes this file' }
}

/** The "Host / user" cell of a member: "host · user", whichever it has. */
export const whoOf = (member) => [member.host, member.username].filter(Boolean).join(' · ')

/** The "Section / source" cell: "Event Logs · windows.evtx"-like, from the member's kind and source. */
export const whatOf = (member) =>
  member.kind ? [sectionLabel(member.kind), member.source].filter(Boolean).join(' · ') : ''

/** How far an import is, 0 to 100, from `members.importing` ({ total, done, already, failed }). */
export function importPercent(importing) {
  const total = Number(importing?.total ?? 0)
  if (!(total > 0)) return null
  const finished = Number(importing.done ?? 0) + Number(importing.already ?? 0) + Number(importing.failed ?? 0)
  return Math.max(0, Math.min(100, Math.round((finished / total) * 100)))
}

/** "3 of 5 imported · 1 already there · 0 failed" while it goes. */
export function importText(importing) {
  if (!importing) return ''
  const parts = [`${importing.done ?? 0} of ${importing.total ?? 0} imported`]
  if (importing.already) parts.push(`${importing.already} already there`)
  if (importing.failed) parts.push(`${importing.failed} failed`)
  return parts.join(' · ')
}

/** What the "Import" button says and how many files it imports: the selection, else everything importable. */
export function importAction(selected, importable) {
  const count = selected > 0 ? selected : importable
  return { count, label: count === 1 ? 'Import 1 file' : `Import ${count} files`, all: selected === 0 }
}

/** The body of the import request: the numbers picked, or all of them (limited to the kinds ticked). */
export function importBody(picked, kinds = []) {
  if (picked.length > 0) return { members: [...picked].sort((a, b) => a - b) }
  return kinds.length > 0 ? { all: true, kinds } : { all: true }
}

/** The state of a collection row as a short phrase for the Collections block. */
export function collectionState(source) {
  switch (source?.state) {
    case 'listing':
      return 'listing the files'
    case 'importing':
      return 'importing'
    case 'failed':
      return 'could not be listed'
    case 'listed':
      return 'listed'
    case 'done':
      return 'imported'
    case 'queued':
    case 'parsing':
      return 'being read'
    default:
      return source?.state ?? ''
  }
}

/** Whether the row is working (the page asks again every few seconds). */
export const isWorking = (source) => ['listing', 'importing', 'queued', 'parsing'].includes(source?.state)

/** "12 files found · 3 imported" for the Collections block. */
export function collectionCounts(source) {
  const found = source?.inFile ?? source?.members?.members ?? null
  const imported = source?.kept ?? source?.members?.imported ?? 0
  return { found, imported }
}

/** The line a source that came out of a collection says: "from <collection>: <path in the zip>"; '' for any other. */
export function fromCollection(source) {
  if (!source?.collectionId) return ''
  const name = source.collectionName || 'a collection'
  return source.filePath ? `from ${name}: ${source.filePath}` : `from ${name}`
}

/** The names of the files that should open the collection dialog (a zip or a psort export), by name. */
export const COLLECTION_FILE = /(\.zip$)|(^|[\\/])plaso\.(jsonl|csv)$|\.plaso\.(jsonl|csv)$/i

/** Whether a file, by its name, is for a collection (it is sent with `kind: "auto"` and opens the list). */
export const looksLikeCollection = (name) => COLLECTION_FILE.test(String(name ?? ''))

/** The page that shows a section of the server, for "went to" messages: `{ tab, label }`. */
export const PAGE_OF_KIND = {
  eventlog: { tab: 'eventlogs', label: 'Event Logs' },
  syslog: { tab: 'eventlogs', label: 'Event Logs' },
  endpoint: { tab: 'endpoint', label: 'Endpoint Artifacts' },
  browser: { tab: 'browser', label: 'Browser Forensics' },
  commands: { tab: 'commands', label: 'Command History' },
  disk: { tab: 'disk', label: 'Disk (NTFS)' },
  collection: { tab: 'evidence', label: 'Evidence' },
}

/** `{ tab, label }` of where a file went, from the upload's answer (`kind`); null when the server did not say. */
export const placeOf = (kind) => PAGE_OF_KIND[kind] ?? null

/** "Security.evtx → Event Logs": what the toast says of a file that was placed. */
export function placedText(fileName, kind) {
  const place = placeOf(kind)
  return place ? `${fileName} → ${place.label}` : fileName
}
