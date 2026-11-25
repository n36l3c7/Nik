/*
 * What the Disk (NTFS) page works out: its two selector tabs ($MFT and $J, each a source of the `disk`
 * section), the expected files with where to find them, the filters of each table and how a record reads.
 * The worker writes `ntfs.mft` (one record per file entry, `type` file) and `ntfs.usnjrnl` (one per journal
 * record, `type` usn); the fields of a record are in its `data` (workers/forensics/.../parsers/mft.py and
 * usnjrnl.py). These tables hold millions of rows: everything here is a filter for the server to apply.
 */

export const DISK_KIND = 'disk'
export const MFT_SOURCE = 'ntfs.mft'
export const USN_SOURCE = 'ntfs.usnjrnl'

/** The two selector tabs, with the expected file of each and where to find it. */
export const DISK_SOURCES = [
  {
    id: 'mft',
    key: MFT_SOURCE,
    label: '$MFT',
    hint: '$MFT in the root of the NTFS volume, hidden and locked on a live system. Copy it with KAPE (target $MFT), Velociraptor (Windows.KapeFiles.Targets), or FTK Imager ([root]\\$MFT → Export Files). From an image with The Sleuth Kit: icat image.dd 0 > MFT.',
    searchPlaceholder: 'Search the paths…',
    noun: 'entries',
  },
  {
    id: 'usn',
    key: USN_SOURCE,
    label: '$J',
    hint: '$J, the data stream of \\$Extend\\$UsnJrnl. It is sparse: keep the zeros. KAPE target $J, Velociraptor Windows.KapeFiles.Targets, or FTK Imager ([root]\\$Extend\\$UsnJrnl → $J). Collectors name it $J, $UsnJrnl_$J or C_$Extend_$UsnJrnl_$J.',
    searchPlaceholder: 'Search the names…',
    noun: 'journal records',
  },
]

export const diskSourceById = (id) => DISK_SOURCES.find((item) => item.id === id) ?? DISK_SOURCES[0]

/** What SourceFiles needs as `expected`: one grey row per file, with where to find it. */
export const expectedDiskFile = (id) => {
  const item = diskSourceById(id)
  return [{ key: item.key, label: item.label, hint: item.hint }]
}

/** The `source` of a file as the tab of the selector it belongs to ('' when it belongs to neither). */
export const diskTabOf = (source) => DISK_SOURCES.find((item) => item.key === source)?.id ?? ''

/** The items of the selector: label, records (from the stack of `source`) and the dot of a file read in part. */
export function diskItems(counts = {}, sources = []) {
  return DISK_SOURCES.map((item) => ({
    id: item.id,
    label: item.label,
    count: counts[item.key] ?? 0,
    partial: sources.some(
      (source) => source.source === item.key && source.read === 'partial' && !source.seen && source.state !== 'absent',
    ),
  }))
}

/* ---- $MFT: the filters of the entries ---- */

/*
 * Four independent questions about an entry, each a pair of `dataKey` and `dataValue` (the API takes up to four
 * pairs at once, paired by position): state, type, an alternate data stream (`data.ads`, written by the worker)
 * and the zone of the download mark. Each has an "any" option that sets nothing.
 */
export const MFT_CHOICES = [
  {
    name: 'state',
    label: 'State',
    key: 'inUse',
    options: [
      { value: '', label: 'Any state' },
      { value: 'in-use', label: 'In use', dataValue: 'true' },
      { value: 'deleted', label: 'Deleted', dataValue: 'false' },
    ],
  },
  {
    name: 'type',
    label: 'Entry type',
    key: 'isDirectory',
    options: [
      { value: '', label: 'Any type' },
      { value: 'file', label: 'File', dataValue: 'false' },
      { value: 'directory', label: 'Directory', dataValue: 'true' },
    ],
  },
  {
    name: 'ads',
    label: 'Alternate stream',
    key: 'ads',
    options: [
      { value: '', label: 'Any' },
      { value: 'has', label: 'Has an alternate stream', dataValue: 'true' },
    ],
  },
  {
    name: 'zone',
    label: 'Zone',
    key: 'zoneId',
    options: [
      { value: '', label: 'Any zone' },
      { value: 'internet', label: 'Internet (3)', dataValue: '3' },
      { value: 'restricted', label: 'Restricted (4)', dataValue: '4' },
    ],
  },
]

const asList = (value) => (value === undefined || value === null || value === '' ? [] : [].concat(value))

/** The pairs of data filters in force, as `[key, value]`. */
const pairsOf = (filters = {}) => {
  const keys = asList(filters.dataKey)
  const values = asList(filters.dataValue)
  return keys.map((key, index) => [String(key), String(values[index] ?? '')])
}

/** The filters with these pairs (none at all when there are none: an empty list says nothing). */
function withPairs(filters, pairs) {
  const { dataKey: _key, dataValue: _value, ...rest } = filters
  return pairs.length
    ? { ...rest, dataKey: pairs.map(([key]) => key), dataValue: pairs.map(([, value]) => value) }
    : rest
}

/** The option of one choice ('state', 'type', 'ads', 'zone') the filters in force correspond to ('' for none). */
export function mftChoiceOf(filters = {}, name) {
  const choice = MFT_CHOICES.find((item) => item.name === name)
  const pair = pairsOf(filters).find(([key]) => key === choice?.key)
  return choice?.options.find((option) => pair && option.dataValue === pair[1])?.value ?? ''
}

/** The filters with one choice set (replacing its own pair, leaving the other choices alone). */
export function withMftChoice(filters = {}, name, value) {
  const choice = MFT_CHOICES.find((item) => item.name === name)
  if (!choice) return filters
  const option = choice.options.find((item) => item.value === value)
  const pairs = pairsOf(filters).filter(([key]) => key !== choice.key)
  if (option?.dataValue !== undefined) pairs.push([choice.key, option.dataValue])
  return withPairs(filters, pairs)
}

/** The filters of the "Deleted" stat card. */
export const deletedFilters = (base = {}) => withMftChoice(base, 'state', 'deleted')

/* ---- $MFT: the columns ---- */

/** The keys of `data` the table asks for (the server gives 12 at most): the times, and what is not in the summary. */
export const MFT_FIELDS = [
  'size',
  'isDirectory',
  'siBeforeFn',
  'streams',
  'zoneId',
  'siModified',
  'siMftModified',
  'siAccessed',
  'fnCreated',
  'fnModified',
  'fnMftModified',
  'fnAccessed',
]

/** The seven times besides the one the table sorts by (`ts`, the creation time of the standard information). */
export const MFT_TIMES = [
  { key: 'siModified', label: 'Modified (SI)' },
  { key: 'siMftModified', label: 'MFT modified (SI)' },
  { key: 'siAccessed', label: 'Accessed (SI)' },
  { key: 'fnCreated', label: 'Created (FN)' },
  { key: 'fnModified', label: 'Modified (FN)' },
  { key: 'fnMftModified', label: 'MFT modified (FN)' },
  { key: 'fnAccessed', label: 'Accessed (FN)' },
]

export const USN_FIELDS = ['name', 'reasons', 'fileEntry', 'parentEntry']

export const TIMESTOMP_HINT =
  'A hint, not a finding: the times look set by hand (all whole seconds, and created before its name was written).'

const DELETED_SUFFIX = / \[deleted\]$/

/** The path of an entry, from the summary the worker writes ("path" or "path [deleted]"). */
export const pathOf = (row) => String(row?.summary ?? '').replace(DELETED_SUFFIX, '')

/** Whether an entry is deleted (not in use): the worker marks the summary of such an entry. */
export const isDeleted = (row) => DELETED_SUFFIX.test(String(row?.summary ?? ''))

/** The names of the alternate streams of an entry (the unnamed data stream is not one), as text. */
export function streamsText(data) {
  const streams = Array.isArray(data?.streams) ? data.streams : []
  return streams
    .filter((stream) => stream?.name)
    .map((stream) => String(stream.name))
    .join(', ')
}

/** The reasons of a journal record as a list of names. */
export const reasonsOf = (data) => (Array.isArray(data?.reasons) ? data.reasons.map(String) : [])

/*
 * The single reasons of a journal record, as the parser names them (usnjrnl.py, REASONS). A record holds a list
 * of them and the filter asks whether the list holds one (`dataHas=reasons:<name>`), so a combination is found
 * by any of its parts.
 */
export const USN_REASONS = [
  'DATA_OVERWRITE',
  'DATA_EXTEND',
  'DATA_TRUNCATION',
  'NAMED_DATA_OVERWRITE',
  'NAMED_DATA_EXTEND',
  'NAMED_DATA_TRUNCATION',
  'FILE_CREATE',
  'FILE_DELETE',
  'EA_CHANGE',
  'SECURITY_CHANGE',
  'RENAME_OLD_NAME',
  'RENAME_NEW_NAME',
  'INDEXABLE_CHANGE',
  'BASIC_INFO_CHANGE',
  'HARD_LINK_CHANGE',
  'COMPRESSION_CHANGE',
  'ENCRYPTION_CHANGE',
  'OBJECT_ID_CHANGE',
  'REPARSE_POINT_CHANGE',
  'STREAM_CHANGE',
  'TRANSACTED_CHANGE',
  'INTEGRITY_CHANGE',
  'CLOSE',
]

/** The options of the "Reason" select: any, then each reason. */
export const reasonOptions = () => [
  { value: '', label: 'Any reason' },
  ...USN_REASONS.map((name) => ({ value: name, label: name })),
]

const REASON_PREFIX = 'reasons:'

/** The filters with the reason applied (the `dataHas` filter replaced, never added to). */
export const withReason = (filters = {}, reason) => {
  const { dataHas: _has, ...rest } = filters
  return reason ? { ...rest, dataHas: [`${REASON_PREFIX}${reason}`] } : rest
}

/** The reason the filters ask for ('' for none). */
export const reasonOf = (filters = {}) => {
  const held = asList(filters.dataHas).find((text) => String(text).startsWith(REASON_PREFIX))
  return held ? String(held).slice(REASON_PREFIX.length) : ''
}
