import LevelBadge from './LevelBadge.jsx'
import { tagChips, tagUrl } from '../../domain/detections.js'

/**
 * What the rules found in one record: each detection with its level, title, author and ATT&CK tags.
 * The author is always shown: the licence of the rules asks for it. `detections` are the ones of
 * `GET .../records/{id}` (`ruleId, ruleTitle, ruleAuthor, level, tags`); nothing is drawn for none.
 *
 * @param {{ detections: object[] | null | undefined, title?: string }} props
 */
export default function DetectionsPanel({ detections, title = 'Detections' }) {
  if (!detections || detections.length === 0) return null
  return (
    <section aria-label={title} className="border-b border-line-soft p-4">
      <h3 className="mb-2 text-sm font-semibold">
        {title} <span className="font-mono text-xs font-normal text-fg-muted">{detections.length}</span>
      </h3>
      <ul className="m-0 list-none space-y-3 p-0">
        {detections.map((found) => (
          <li key={found.ruleId} className="space-y-1 text-[13px]">
            <div className="flex flex-wrap items-center gap-2">
              <LevelBadge level={found.level} />
              <span className="font-medium">{found.ruleTitle || found.ruleId}</span>
            </div>
            <p className="m-0 text-xs text-fg-muted">
              {found.ruleAuthor ? `Rule by ${found.ruleAuthor}` : 'No author named'}
            </p>
            <p className="m-0 flex flex-wrap gap-1">
              {tagChips(found.tags).map((tag) => {
                const url = tagUrl(tag)
                const chip = 'border border-line bg-canvas px-1.5 py-px font-mono text-[11px] text-fg-muted'
                return url ? (
                  <a
                    key={tag}
                    href={url}
                    target="_blank"
                    rel="noreferrer noopener"
                    className={`${chip} text-link hover:underline`}
                  >
                    {tag}
                  </a>
                ) : (
                  <span key={tag} className={chip}>
                    {tag}
                  </span>
                )
              })}
            </p>
          </li>
        ))}
      </ul>
    </section>
  )
}
