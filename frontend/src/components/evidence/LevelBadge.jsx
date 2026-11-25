import { Badge } from '../ui/index.js'
import { levelColor, levelName, levelOf } from '../../domain/detections.js'

/**
 * The level of a detection as the badge every page uses: the name of the level, coloured by it. A value
 * that is no level (a record with no detection has `level: null`) draws nothing, or `empty` when given.
 *
 * @param {{ level: number | string | null | undefined, empty?: import('react').ReactNode }} props
 */
export default function LevelBadge({ level, empty = null }) {
  if (!levelOf(level)) return empty
  return (
    <Badge color={levelColor(level)} className={levelOf(level).level === 5 ? 'font-bold uppercase' : ''}>
      {levelName(level)}
    </Badge>
  )
}
