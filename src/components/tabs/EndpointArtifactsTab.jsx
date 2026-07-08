import { Clock, Database, HardDrive, Info, Plus, Terminal } from 'lucide-react'
import { Badge, Button, EmptyState } from '../ui'

/*
 * "Endpoint Artifacts" tab — polished placeholder, ready for expansion.
 * The incident data structure (data.endpoint) is already registered in
 * config/tabs.js: to implement the real analysis just replace this
 * component. See README.md § "Adding a new analysis tab".
 */

/** Planned analysis modules, shown as disabled mini-cards. */
const UPCOMING_MODULES = [
  {
    id: 'amcache',
    title: 'Amcache/Shimcache',
    icon: Database,
    description:
      'Program execution evidence from Windows compatibility registries.',
  },
  {
    id: 'prefetch',
    title: 'Prefetch',
    icon: Clock,
    description:
      '.pf files: first/last execution and application launch frequency.',
  },
  {
    id: 'evtx',
    title: 'Event Logs (EVTX)',
    icon: Terminal,
    description:
      'Parsing of Windows Event Logs: logons, services, PowerShell.',
  },
]

/**
 * @param {{ incident: object }} props — the active incident (reserved for
 * future implementation: data will live in incident.data.endpoint)
 */
export default function EndpointArtifactsTab({ incident }) {
  return (
    <div className="mx-auto max-w-4xl space-y-6">
      {/* Main empty state with the message required by the SPEC */}
      <div className="rounded-xl border border-slate-200 bg-white py-10 dark:border-slate-800 dark:bg-slate-900">
        <EmptyState
          icon={HardDrive}
          title="Endpoint Artifacts"
          message="Ready for expansion: section dedicated to analyzing Amcache, Shimcache, Prefetch or Windows Event Logs."
        />
      </div>

      {/* Mini-cards for upcoming modules: disabled and dashed */}
      <div className="grid gap-4 sm:grid-cols-3">
        {UPCOMING_MODULES.map(({ id, title, icon: Icon, description }) => (
          <div
            key={id}
            aria-disabled="true"
            className="select-none rounded-xl border border-dashed border-slate-300 bg-white/60 p-4 opacity-70 dark:border-slate-700 dark:bg-slate-900/60"
          >
            <div className="flex items-center gap-2">
              <span className="rounded-lg bg-slate-100 p-2 text-slate-400 dark:bg-slate-800 dark:text-slate-500">
                <Icon size={18} />
              </span>
              <span className="min-w-0 truncate text-sm font-medium text-slate-600 dark:text-slate-300">
                {title}
              </span>
              <Badge color="slate" className="ml-auto shrink-0">
                Coming soon
              </Badge>
            </div>
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              {description}
            </p>
          </div>
        ))}
      </div>

      {/* Future action: intentionally disabled */}
      <div className="flex justify-center">
        <Button variant="secondary" icon={Plus} disabled>
          Add data source (coming soon)
        </Button>
      </div>

      {/* Pointer to the developer guide */}
      <p className="flex items-center justify-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
        <Info size={14} className="shrink-0" />
        To implement this tab see README.md § &#39;Adding a new analysis
        tab&#39;.
      </p>
    </div>
  )
}
