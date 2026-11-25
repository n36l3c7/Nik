import { Select } from '../ui/index.js'
import LevelBadge from './LevelBadge.jsx'
import { LEVEL_FILTER_OPTIONS, levelLabel, minLevelText } from '../../domain/detections.js'

/*
 * What every table of host records shares about detections (the rules that matched a record): the column
 * with the record's level, and the "Level" filter of the toolbar. `level` is the highest level of the
 * record's detections, null for none; as a filter it is a minimum.
 */

/** The "Detections" column of a ServerTable over records. Its menu filters on "at least this level". */
export const detectionsColumn = {
  key: 'detections',
  label: 'Detections',
  filterKey: 'level',
  hideable: true,
  value: (row) => row.level ?? null,
  filterText: (value) => `Filter: ${levelLabel(value).toLowerCase()} and above`,
  chipLabel: minLevelText,
  render: (row) => <LevelBadge level={row.level} empty={<span className="sr-only">None</span>} />,
}

/**
 * The "Detection" select of the toolbar (the minimum level of a record): any, or a minimum level. Put 'level' in the table's `hideChips`, the
 * select says it already.
 *
 * @param {{ filters: object, onChange: (value: string) => void }} props
 */
export function LevelFilter({ filters, onChange }) {
  return (
    <Select label="Detection" value={String(filters.level ?? '')} onChange={onChange} options={LEVEL_FILTER_OPTIONS} />
  )
}
