import { BellRing, Eye, FileUp, Plus } from 'lucide-react'
import { useIocLibrary } from '../../context/IocLibraryContext.jsx'
import { QUICK_FILTERS } from '../../domain/iocLibrary.js'
import { Button } from '../ui/index.js'

/*
 * The IoC panel of the sidebar: quick filters over the whole library, the
 * alerts of the watched lists, and the lists. The table is in the main area.
 */

function Entry({ active, onClick, label, count, icon: Icon = null, tone = '' }) {
  return (
    <li>
      <button
        type="button"
        onClick={onClick}
        aria-current={active ? 'true' : undefined}
        className={[
          'flex w-full items-center gap-2 px-3 py-1.5 text-left text-[13px] transition-colors',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent',
          active ? 'bg-panel text-fg shadow-[inset_2px_0_0_var(--color-accent)]' : 'text-fg-muted hover:bg-panel/60',
        ].join(' ')}
      >
        {Icon && <Icon className={`h-3.5 w-3.5 shrink-0 ${tone}`} aria-hidden="true" />}
        <span className="min-w-0 flex-1 truncate">{label}</span>
        <span className={`font-mono text-[11px] tabular-nums ${tone || 'text-fg-subtle'}`}>{count}</span>
      </button>
    </li>
  )
}

/** @param {{ width: number }} props */
export default function IocsPanel({ width }) {
  const { view, openView, quick, setQuick, counts, lists, alerts, openAdd } = useIocLibrary()
  return (
    <aside
      aria-label="IoCs panel"
      style={{ width }}
      className="flex h-full shrink-0 flex-col border-r border-line bg-sunken"
    >
      <div className="flex items-center gap-2 border-b border-line px-3 py-3">
        <p className="min-w-0 flex-1 truncate font-mono text-[11px] tracking-wider text-fg-muted">
          IOCS · {counts.all}
        </p>
        <Button size="sm" icon={Plus} onClick={() => openAdd()}>
          Add
        </Button>
      </div>
      <nav aria-label="IoC views" className="flex-1 overflow-y-auto py-2">
        <ul>
          {QUICK_FILTERS.map((filter) => (
            <Entry
              key={filter.id}
              label={filter.label}
              count={counts[filter.count] ?? 0}
              active={view?.kind === 'all' && quick === filter.id}
              onClick={() => {
                setQuick(filter.id)
                openView({ kind: 'all' })
              }}
            />
          ))}
          <Entry
            label="Alerts"
            icon={BellRing}
            tone={alerts > 0 ? 'text-high' : ''}
            count={alerts}
            active={view?.kind === 'alerts'}
            onClick={() => openView({ kind: 'alerts' })}
          />
        </ul>
        <p className="px-3 pb-1 pt-4 font-mono text-[11px] uppercase tracking-wider text-fg-muted">
          Lists · {lists.length}
        </p>
        {lists.length === 0 ? (
          <p className="px-3 py-1 text-xs text-fg-subtle">
            None yet. Select indicators and choose &quot;Add to a list&quot;, or group them when you add them.
          </p>
        ) : (
          <ul>
            {lists.map((list) => (
              <Entry
                key={list.id}
                label={list.name}
                icon={list.watch ? Eye : null}
                count={list.count}
                active={view?.kind === 'list' && view.id === list.id}
                onClick={() => openView({ kind: 'list', id: list.id })}
              />
            ))}
          </ul>
        )}
      </nav>
      <div className="border-t border-line px-3 py-2.5">
        <Button
          size="sm"
          variant="secondary"
          icon={FileUp}
          className="w-full"
          onClick={() => openAdd({ origin: 'import' })}
        >
          Import a file
        </Button>
      </div>
    </aside>
  )
}
