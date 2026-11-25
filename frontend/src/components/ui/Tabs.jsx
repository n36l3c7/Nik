import { useRef } from 'react'
import { tabStop, tabTarget } from '../../domain/tabs.js'

/**
 * Tabs: one row of tabs, in two looks.
 *
 *  - `selector`: square pills in a bordered bar. It chooses what to look at (a browser, a shell, a
 *    channel, a host); the count sits at the right of the label, and a small yellow dot says that a
 *    file behind the tab was read only in part.
 *  - `section`: the underline of Mail, Malware and Network. It chooses which part of the same thing.
 *
 * `items`: `{ id, label, count?, partial?, disabled? }`. `value` is the id of the selected one;
 * `onChange(id)` is called for the one chosen. `label` is the accessible name of the row.
 *
 * It is a tablist: the selected tab is the one Tab stop, Left and Right move between the tabs (and
 * choose them), Home and End go to the ends. The panel the tabs choose is the caller's: give it
 * `role="tabpanel"` and `aria-labelledby={tabId(id)}` when it wants the link spoken.
 */

const SELECTOR = {
  bar: 'inline-flex max-w-full flex-wrap gap-1.5 border border-line bg-panel p-2',
  tab: 'flex items-center gap-2 whitespace-nowrap border px-3.5 py-1.5 text-sm transition-colors',
  on: 'border-accent-strong bg-accent-soft text-accent-fg',
  off: 'border-transparent text-fg hover:bg-raised',
  count: 'bg-raised px-1.5 font-mono text-xs tabular-nums text-fg-muted',
  countOn: 'px-1.5 font-mono text-xs tabular-nums text-accent-fg',
}

const SECTION = {
  bar: 'flex flex-wrap gap-1 border-b border-line',
  tab: '-mb-px flex items-center gap-2 whitespace-nowrap border-b-2 px-3 py-2 text-sm font-medium transition-colors',
  on: 'border-accent-strong text-accent',
  off: 'border-transparent text-fg-muted hover:text-fg',
  count: 'bg-canvas px-1.5 text-xs tabular-nums text-fg-muted',
  countOn: 'bg-canvas px-1.5 text-xs tabular-nums text-fg-muted',
}

const FOCUS = 'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/** The id of the tab element of an item, for the `aria-labelledby` of its panel. */
export const tabId = (group, id) => `tab-${group}-${id}`

export default function Tabs({
  variant = 'section',
  items,
  value,
  onChange,
  label,
  idPrefix = 'tabs',
  className = '',
}) {
  const look = variant === 'selector' ? SELECTOR : SECTION
  const refs = useRef([])
  const stop = tabStop(value, items)

  const onKeyDown = (event, index) => {
    const target = tabTarget(event.key, index, items)
    if (target === null) return
    event.preventDefault()
    refs.current[target]?.focus()
    onChange?.(items[target].id)
  }

  return (
    <div role="tablist" aria-label={label} className={`${look.bar} ${className}`}>
      {items.map((item, index) => {
        const active = item.id === value
        const hasCount = item.count !== undefined && item.count !== null
        return (
          <button
            key={item.id}
            ref={(node) => {
              refs.current[index] = node
            }}
            id={tabId(idPrefix, item.id)}
            type="button"
            role="tab"
            aria-selected={active}
            disabled={item.disabled}
            tabIndex={index === stop ? 0 : -1}
            onClick={() => onChange?.(item.id)}
            onKeyDown={(event) => onKeyDown(event, index)}
            className={[
              look.tab,
              FOCUS,
              active ? look.on : look.off,
              item.disabled ? 'cursor-not-allowed opacity-50' : '',
            ].join(' ')}
          >
            {item.label}
            {hasCount && <span className={active ? look.countOn : look.count}>{item.count}</span>}
            {item.partial && (
              <span
                role="img"
                aria-label="read in part"
                title="read in part"
                className="h-[7px] w-[7px] rounded-full bg-med"
              />
            )}
          </button>
        )
      })}
    </div>
  )
}
